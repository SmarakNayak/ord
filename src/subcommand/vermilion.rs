use self::migrate::Migrator;

use super::*;
use axum_server::Handle;
use serde_aux::prelude::*;
use tokio::io::AsyncReadExt;
use crate::subcommand::server;
use crate::index::fetcher;
use crate::Charm;

use tokio::sync::Semaphore;
use tokio::sync::Mutex;
use tokio::task::JoinSet;
use serde::Serialize;
use sha256::digest;

use aws_sdk_s3 as s3;	
use s3::primitives::ByteStream;	
use s3::error::ProvideErrorMetadata;

use axum::{
  routing::get,
  Json, 
  Router,
  extract::{Path, State, Query},
  body::{Body, BoxBody},
  middleware::map_response,
  http::StatusCode,
  http::HeaderMap,
  response::IntoResponse,
};
use axum_session::{Session, SessionNullPool, SessionConfig, SessionStore, SessionLayer};

use tower_http::trace::TraceLayer;
use tower_http::trace::DefaultMakeSpan;
use tower_http::cors::{Any, CorsLayer};
use tracing::Span;
use http::{Request, Response};
use tracing::Level as TraceLevel;

use std::collections::BTreeSet;
use std::net::SocketAddr;
use std::thread::JoinHandle;
use rand::Rng;
use rand::SeedableRng;
use itertools::Itertools;

use serde_json::{Value as JsonValue, value::Number as JsonNumber};
use ciborium::value::Value as CborValue;
use base64::engine::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;

use deadpool_postgres::{ManagerConfig, Pool as deadpool, RecyclingMethod};
use tokio_postgres::NoTls;
use tokio_postgres::binary_copy::BinaryCopyInWriter;
use tokio_postgres::types::{ToSql, Type};
use futures::pin_mut;

#[derive(Debug, Parser, Clone)]
pub(crate) struct Vermilion {
  #[arg(
    long,
    help = "Listen on <ADDRESS> for incoming requests. [default: 0.0.0.0]"
  )]
  pub(crate) address: Option<String>,
  #[arg(
    long,
    help = "Request ACME TLS certificate for <ACME_DOMAIN>. This ord instance must be reachable at <ACME_DOMAIN>:443 to respond to Let's Encrypt ACME challenges."
  )]
  pub(crate) acme_domain: Vec<String>,
  #[arg(
    long,
    help = "Use <CSP_ORIGIN> in Content-Security-Policy header. Set this to the public-facing URL of your ord instance."
  )]
  pub(crate) csp_origin: Option<String>,
  #[arg(
    long,
    help = "Listen on <HTTP_PORT> for incoming HTTP requests. [default: 80]"
  )]
  pub(crate) http_port: Option<u16>,
  #[arg(
    long,
    group = "port",
    help = "Listen on <HTTPS_PORT> for incoming HTTPS requests. [default: 443]"
  )]
  pub(crate) https_port: Option<u16>,
  #[arg(long, help = "Store ACME TLS certificates in <ACME_CACHE>.")]
  pub(crate) acme_cache: Option<PathBuf>,
  #[arg(long, help = "Provide ACME contact <ACME_CONTACT>.")]
  pub(crate) acme_contact: Vec<String>,
  #[arg(long, help = "Serve HTTP traffic on <HTTP_PORT>.")]
  pub(crate) http: bool,
  #[arg(long, help = "Serve HTTPS traffic on <HTTPS_PORT>.")]
  pub(crate) https: bool,
  #[arg(long, help = "Redirect HTTP traffic to HTTPS.")]
  pub(crate) redirect_http_to_https: bool,
  #[arg(long, help = "Disable JSON API.")]
  pub(crate) disable_json_api: bool,
  #[arg(
    long,
    help = "Decompress encoded content. Currently only supports brotli. Be careful using this on production instances. A decompressed inscription may be arbitrarily large, making decompression a DoS vector."
  )]
  pub(crate) decompress: bool,
  #[arg(long, alias = "nosync", help = "Do not update the index.")]
  pub(crate) no_sync: bool,
  #[arg(
    long,
    help = "Proxy `/content/INSCRIPTION_ID` requests to `<CONTENT_PROXY>/content/INSCRIPTION_ID` if the inscription is not present on current chain."
  )]
  pub(crate) content_proxy: Option<Url>,
  #[arg(
    long,
    default_value = "5s",
    help = "Poll Bitcoin Core every <POLLING_INTERVAL>."
  )]
  pub(crate) polling_interval: humantime::Duration,
  #[arg(
    long,
    help = "Listen on <HTTP_PORT> for incoming REST requests. [default: 81]."
  )]
  pub(crate) api_http_port: Option<u16>,
  #[arg(
    long,
    help = "Number of threads to use when uploading content and metadata. [default: 1]."
  )]
  pub(crate) n_threads: Option<u16>,
  #[arg(long, help = "Only run api server, do not run indexer. [default: false].")]
  pub(crate) run_api_server_only: bool,
  #[arg(long, help = "Run migration script. [default: false].")]
  pub(crate) run_migration_script: bool,
}

#[derive(Clone, Serialize)]
pub struct Metadata {  
  sequence_number: i64,
  id: String,
  content_length: Option<i64>,
  content_type: Option<String>,
  content_encoding: Option<String>,
  content_category: String,
  genesis_fee: i64,
  genesis_height: i64,
  genesis_transaction: String,
  pointer: Option<i64>,
  number: i64,
  parents: Vec<String>,
  delegate: Option<String>,
  metaprotocol: Option<String>,
  on_chain_metadata: serde_json::Value,
  sat: Option<i64>,
  sat_block: Option<i64>,
  satributes: Vec<String>,
  charms: Vec<String>,
  timestamp: i64,
  sha256: Option<String>,
  text: Option<String>,
  referenced_ids: Vec<String>,
  is_json: bool,
  is_maybe_json: bool,
  is_bitmap_style: bool,
  is_recursive: bool
}

#[derive(Clone, Serialize)]
pub struct SatMetadata {
  sat: i64,
  satributes: Vec<String>,
  decimal: String,
  degree: String,
  name: String,
  block: i64,
  cycle: i64,
  epoch: i64,
  period: i64,
  third: i64,
  rarity: String,
  percentile: String,
  timestamp: i64
}

#[derive(Serialize)]
pub struct Satribute {
  sat: i64,
  satribute: String,
}

#[derive(Serialize)]
pub struct ContentBlob {
  sha256: String,
  content: Vec<u8>,
  content_type: String,
  content_encoding: Option<String>,
}

#[derive(Clone, Serialize)]
pub struct Transfer {
  id: String,
  block_number: i64,
  block_timestamp: i64,
  satpoint: String,
  tx_offset: i64,
  transaction: String,
  vout: i32,
  offset: i64,
  address: String,
  previous_address: String,
  price: i64,
  tx_fee: i64,
  tx_size: i64,
  is_genesis: bool
}

#[derive(Clone, Serialize)]
pub struct TransferWithMetadata {
  id: String,
  block_number: i64,
  block_timestamp: i64,
  satpoint: String,
  tx_offset: i64,
  transaction: String,
  vout: i32,
  offset: i64,
  address: String,
  is_genesis: bool,
  content_length: Option<i64>,
  content_type: Option<String>,
  content_encoding: Option<String>,
  content_category: String,
  genesis_fee: i64,
  genesis_height: i64,
  genesis_transaction: String,
  pointer: Option<i64>,
  number: i64,
  sequence_number: Option<i64>,
  sat: Option<i64>,
  sat_block: Option<i64>,
  satributes: Vec<String>,
  charms: Vec<String>,
  parents: Vec<String>,
  delegate: Option<String>,
  metaprotocol: Option<String>,
  on_chain_metadata: serde_json::Value,
  timestamp: i64,
  sha256: Option<String>,
  text: Option<String>,
  referenced_ids: Vec<String>,
  is_json: bool,
  is_maybe_json: bool,
  is_bitmap_style: bool,
  is_recursive: bool
}

#[derive(Clone, Serialize)]
pub struct BlockStats {
  block_number: i64,
  block_timestamp: Option<i64>,
  block_tx_count: Option<i64>,
  block_size: Option<i64>,
  block_fees: Option<i64>,
  min_fee: Option<i64>,
  max_fee: Option<i64>,
  average_fee: Option<i64>
}

#[derive(Clone, Serialize)]
pub struct InscriptionBlockStats {
  block_number: i64,
  block_inscription_count: Option<i64>,
  block_inscription_size: Option<i64>,
  block_inscription_fees: Option<i64>,
  block_transfer_count: Option<i64>,
  block_transfer_size: Option<i64>,
  block_transfer_fees: Option<i64>,
  block_volume: Option<i64>,
}

#[derive(Clone, Serialize)]
pub struct CombinedBlockStats {
  block_number: i64,
  block_timestamp: Option<i64>,
  block_tx_count: Option<i64>,
  block_size: Option<i64>,
  block_fees: Option<i64>,
  min_fee: Option<i64>,
  max_fee: Option<i64>,
  average_fee: Option<i64>,
  block_inscription_count: Option<i64>,
  block_inscription_size: Option<i64>,
  block_inscription_fees: Option<i64>,
  block_transfer_count: Option<i64>,
  block_transfer_size: Option<i64>,
  block_transfer_fees: Option<i64>,
  block_volume: Option<i64>,
}

#[derive(Clone, Serialize)]
pub struct SatBlockStats {
  sat_block_number: i64,
  sat_block_timestamp: Option<i64>,
  sat_block_inscription_count: Option<i64>,
  sat_block_inscription_size: Option<i64>,
  sat_block_inscription_fees: Option<i64>,
}

#[derive(Clone, Serialize)]
pub struct Content {
  content: Vec<u8>,
  content_type: Option<String>
}

#[derive(Clone, Serialize)]
pub struct InscriptionNumberEdition {
  id: String,
  number: i64,
  edition: i64,
  total: i64
}

#[derive(Clone, Serialize)]
pub struct InscriptionMetadataForBlock {
  id: String,
  content_length: Option<i64>,
  content_type: Option<String>,
  genesis_fee: i64,
  genesis_height: i64,
  number: i64,
  timestamp: i64
}

#[derive(Deserialize)]
pub struct QueryNumber {
  n: u32
}

#[derive(Deserialize)]
pub struct InscriptionQueryParams {
  content_types: Option<String>,
  satributes: Option<String>,
  charms: Option<String>,
  sort_by: Option<String>,
  page_number: Option<usize>,
  page_size: Option<usize>
}

pub struct ParsedInscriptionQueryParams {
  content_types: Vec<String>,
  satributes: Vec<String>,
  charms: Vec<String>,
  sort_by: String,
  page_number: usize,
  page_size: usize
}

impl From<InscriptionQueryParams> for ParsedInscriptionQueryParams {
  fn from(params: InscriptionQueryParams) -> Self {
      Self {
        content_types: params.content_types.map_or(Vec::new(), |v| v.split(",").map(|s| s.to_string()).collect()),
        satributes: params.satributes.map_or(Vec::new(), |v| v.split(",").map(|s| s.to_string()).collect()),
        charms: params.charms.map_or(Vec::new(), |v| v.split(",").map(|s| s.to_string()).collect()),
        sort_by: params.sort_by.map_or("newest".to_string(), |v| v),
        page_number: params.page_number.map_or(0, |v| v),
        page_size: params.page_size.map_or(10, |v| std::cmp::min(v, 100)),
      }
  }
}

#[derive(Deserialize, Clone)]
pub struct CollectionQueryParams {
  sort_by: Option<String>,
  page_number: Option<usize>,
  page_size: Option<usize>
}

#[derive(Deserialize, Clone)]
pub struct PaginationParams {
  page_number: Option<usize>,
  page_size: Option<usize>
}

pub struct RandomInscriptionBand {
  sequence_number: i64,
  start: f64,
  end: f64
}

pub struct SequenceNumberStatus {
  sequence_number: u64,
  status: String
}

fn deserialize_date<'de, D>(deserializer: D) -> Result<i64, D::Error>
where
  D: serde::Deserializer<'de>,
{
  let s = String::deserialize(deserializer)?;
  let datetime = DateTime::parse_from_rfc2822(&s.as_str());
  match datetime {
      Ok(datetime) => Ok(datetime.timestamp_millis()),
      Err(_) => Err(serde::de::Error::custom("invalid date")),
  }
}

#[derive(Serialize, Deserialize)]
struct CollectionList {
    description: Option<String>,
    #[serde(rename(deserialize = "discord_link"))]
    discord: Option<String>,
    icon: Option<String>,
    inscription_icon: Option<String>,
    name: Option<String>,
    #[serde(rename(deserialize = "slug"))]
    collection_symbol: String,
    #[serde(rename(deserialize = "twitter_link"))]
    twitter: Option<String>,
    #[serde(rename(deserialize = "website_link"))]
    website: Option<String>,
    #[serde(skip_deserializing)]
    supply: Option<i64>,
    //Deprecated:
    image_uri: Option<String>,
    min_inscription_number: Option<i64>,
    max_inscription_number: Option<i64>,
    date_created: Option<i64>
}

#[derive(Deserialize)]
pub struct Collection {
  id: String,
  number: Option<i64>,
  collection_symbol: Option<String>,
  #[serde(rename(deserialize = "meta"))]
  off_chain_metadata: Option<serde_json::Value>
}

#[derive(Serialize)]
pub struct CollectionSummary {
  collection_symbol: String, 
  name: Option<String>,
  description: Option<String>,
  twitter: Option<String>, 
  discord: Option<String>, 
  website: Option<String>,
  total_inscription_fees: Option<i64>,
  total_inscription_size: Option<i64>,
  first_inscribed_date: Option<i64>,
  last_inscribed_date: Option<i64>,
  supply: Option<i64>,
  range_start: Option<i64>,
  range_end: Option<i64>,
  total_volume: Option<i64>,
  total_fees: Option<i64>,
  total_on_chain_footprint: Option<i64>
}

#[derive(Serialize)]
pub struct CollectionHolders {
  collection_symbol: String, 
  collection_holder_count: Option<i64>,
  address: Option<String>,
  address_count: Option<i64>,
}

#[derive(Serialize)]
pub struct InscriptionCollectionData {
  id: String,
  number: i64,
  off_chain_metadata: serde_json::Value,
  collection_symbol: String,
  name: Option<String>,
  image_uri: Option<String>,
  inscription_icon: Option<String>,
  description: Option<String>,
  supply: Option<i64>,
  twitter: Option<String>,
  discord: Option<String>,
  website: Option<String>,
  min_inscription_number: Option<i64>,
  max_inscription_number: Option<i64>,
  date_created: i64
}

#[derive(Serialize)]
pub struct MetadataWithCollectionMetadata {  
  sequence_number: i64,
  id: String,
  content_length: Option<i64>,
  content_type: Option<String>,
  content_encoding: Option<String>,
  content_category: String,
  genesis_fee: i64,
  genesis_height: i64,
  genesis_transaction: String,
  pointer: Option<i64>,
  number: i64,
  parents: Vec<String>,
  delegate: Option<String>,
  metaprotocol: Option<String>,
  on_chain_metadata: serde_json::Value,
  sat: Option<i64>,
  sat_block: Option<i64>,
  satributes: Vec<String>,
  charms: Vec<String>,
  timestamp: i64,
  sha256: Option<String>,
  text: Option<String>,
  referenced_ids: Vec<String>,
  is_json: bool,
  is_maybe_json: bool,
  is_bitmap_style: bool,
  is_recursive: bool,
  collection_symbol: String,
  off_chain_metadata: serde_json::Value,
}

#[derive(Serialize)]
pub struct FullMetadata {  
  sequence_number: i64,
  id: String,
  content_length: Option<i64>,
  content_type: Option<String>,
  content_encoding: Option<String>,
  content_category: String,
  genesis_fee: i64,
  genesis_height: i64,
  genesis_transaction: String,
  pointer: Option<i64>,
  number: i64,
  parents: Vec<String>,
  delegate: Option<String>,
  metaprotocol: Option<String>,
  on_chain_metadata: serde_json::Value,
  sat: Option<i64>,
  sat_block: Option<i64>,
  satributes: Vec<String>,
  charms: Vec<String>,
  timestamp: i64,
  sha256: Option<String>,
  text: Option<String>,
  referenced_ids: Vec<String>,
  is_json: bool,
  is_maybe_json: bool,
  is_bitmap_style: bool,
  is_recursive: bool,
  collection_symbol: Option<String>,
  off_chain_metadata: Option<serde_json::Value>,
  collection_name: Option<String>
}

#[derive(Serialize)]
pub struct SearchResult {
  collections: Vec<CollectionSummary>,
  inscription: Option<FullMetadata>,
  address: Option<String>,
  block: Option<CombinedBlockStats>,
  sat: Option<SatMetadata>
}

#[derive(Clone,PartialEq, PartialOrd, Ord, Eq)]
pub struct IndexerTimings {
  inscription_start: u64,
  inscription_end: u64,
  acquire_permit_start: Instant,
  acquire_permit_end: Instant,
  get_numbers_start: Instant,
  get_numbers_end: Instant,
  get_id_start: Instant,
  get_id_end: Instant,
  get_inscription_start: Instant,
  get_inscription_end: Instant,
  upload_content_start: Instant,
  upload_content_end: Instant,
  get_metadata_start: Instant,
  get_metadata_end: Instant,
  retrieval: Duration,
  insertion: Duration,
  metadata_insertion: Duration,
  sat_insertion: Duration,
  edition_insertion: Duration,
  content_insertion: Duration,
  locking: Duration
}

#[derive(Clone)]
pub struct ApiServerConfig {
  deadpool: deadpool
}

const INDEX_BATCH_SIZE: usize = 10000;

impl Vermilion {
  pub(crate) fn run(self, settings: Settings) -> SubcommandResult {
    //1. Run Vermilion Server
    println!("Vermilion Server Starting");
    let vermilion_server_clone = self.clone();
    let _vermilion_server_thread = vermilion_server_clone.run_vermilion_server(settings.clone());

    if self.run_api_server_only {//If only running api server, block here, early return on ctrl-c
      let rt = Runtime::new().unwrap();
      rt.block_on(async {
        loop {            
          if SHUTTING_DOWN.load(atomic::Ordering::Relaxed) {
            break;
          }
          tokio::time::sleep(Duration::from_secs(10)).await;
        }          
      });
      return Ok(None);
    }

    //2. Run Ordinals Server
    println!("Ordinals Server Starting");
    let index = Arc::new(Index::open(&settings)?);
    let handle = axum_server::Handle::new();
    LISTENERS.lock().unwrap().push(handle.clone());
    let ordinals_server_clone = self.clone();
    let ordinals_server_thread = ordinals_server_clone.run_ordinals_server(settings.clone(), index.clone(), handle);

    //2a. Run Migration script
    let migration_clone = self.clone();
    let migration_script_thread = migration_clone.run_migration_script(settings.clone(), index.clone());

    //3. Run Address Indexer
    println!("Address Indexer Starting");
    let address_indexer_clone = self.clone();
    let address_indexer_thread = address_indexer_clone.run_address_indexer(settings.clone(), index.clone());

    //4. Run Inscription Indexer
    println!("Inscription Indexer Starting");
    let inscription_indexer_clone = self.clone();
    inscription_indexer_clone.run_inscription_indexer(settings.clone(), index.clone()); //this blocks
    println!("Inscription Indexer Stopped");

    //Wait for other threads to finish before exiting
    // vermilion_server_thread.join().unwrap();
    let server_thread_result = ordinals_server_thread.join();
    println!("Server thread joined");
    let address_thread_result = address_indexer_thread.join();
    println!("Address thread joined");
    let migration_thread_result = migration_script_thread.join();
    println!("Migration thread joined");
    if server_thread_result.is_err() {
      println!("Error joining ordinals server thread: {:?}", server_thread_result.unwrap_err());
    }
    if address_thread_result.is_err() {
      println!("Error joining address indexer thread: {:?}", address_thread_result.unwrap_err());
    }
    if migration_thread_result.is_err() {
      println!("Error joining migration script thread: {:?}", migration_thread_result.unwrap_err());
    }
    Ok(None)
  }

  pub(crate) fn run_inscription_indexer(self, settings: Settings, index: Arc<Index>) {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
      let deadpool = match Self::get_deadpool(settings.clone()).await {
        Ok(deadpool) => deadpool,
        Err(err) => {
          println!("Error creating deadpool: {:?}", err);
          return;
        }
      };
      let start_number_override = settings.start_number_override().map(|x| x as u64);
      let s3_config = aws_config::from_env().load().await;
      let s3client = s3::Client::new(&s3_config);
      let s3_bucket_name = settings.s3_bucket_name().unwrap().to_string();
      let s3_upload_start_number = settings.s3_upload_start_number().unwrap_or(0) as u64;
      let s3_head_check = settings.s3_head_check();
      let n_threads = self.n_threads.unwrap_or(1).into();
      let sem = Arc::new(Semaphore::new(n_threads));
      let status_vector: Arc<Mutex<Vec<SequenceNumberStatus>>> = Arc::new(Mutex::new(Vec::new()));
      let timing_vector: Arc<Mutex<Vec<IndexerTimings>>> = Arc::new(Mutex::new(Vec::new()));
      let init_result = Self::initialize_db_tables(deadpool.clone()).await;
      if init_result.is_err() {
        println!("Error initializing db tables: {:?}", init_result.unwrap_err());
        return;
      }
      let collection_data_insert_result = Self::insert_offchain_collection_data(deadpool.clone()).await;
      let collection_summary_result = Self::update_collection_summary(deadpool.clone()).await;
      if collection_data_insert_result.is_err() {
        println!("Error inserting collection list: {:?}", collection_data_insert_result.unwrap_err());
        return;
      }
      if collection_summary_result.is_err() {
        println!("Error updating collection summary: {:?}", collection_summary_result.unwrap_err());
        return;
      }

      let start_number = match start_number_override {
        Some(start_number_override) => start_number_override,
        None => {
          match Self::get_last_number(deadpool.clone()).await {
            Ok(last_number) => (last_number + 1) as u64,
            Err(err) => {
              println!("Error getting last number from db: {:?}, stopping, try restarting process", err);
              return;
            }
          }
        }
      };
      println!("Metadata in db assumed populated up to: {:?}, will only upload metadata for {:?} onwards.", start_number.checked_sub(1), start_number);
      println!("Inscriptions in s3 assumed populated up to: {:?}, will only upload content for {:?} onwards.", std::cmp::max(s3_upload_start_number, start_number).checked_sub(1), std::cmp::max(s3_upload_start_number, start_number));
      let initial = SequenceNumberStatus {
        sequence_number: start_number,
        status: "UNKNOWN".to_string()
      };
      status_vector.lock().await.push(initial);

      // every iteration fetches 1k inscriptions
      let time = Instant::now();
      println!("Starting @ {:?}", time);
      loop {
        let t0 = Instant::now();
        //break if ctrl-c is received
        if SHUTTING_DOWN.load(atomic::Ordering::Relaxed) {
          break;
        }
        let permit = Arc::clone(&sem).acquire_owned().await;
        let cloned_index = index.clone();
        let cloned_deadpool = deadpool.clone();
        let cloned_s3client = s3client.clone();
        let cloned_bucket_name = s3_bucket_name.clone();
        let cloned_status_vector = status_vector.clone();
        let cloned_timing_vector = timing_vector.clone();
        tokio::task::spawn(async move {
          let t1 = Instant::now();
          let _permit = permit;
          let needed_numbers = Self::get_needed_sequence_numbers(cloned_status_vector.clone()).await;
          let mut should_sleep = false;
          let first_number = needed_numbers[0];
          let mut last_number = needed_numbers[needed_numbers.len()-1];
          log::info!("Trying Numbers: {:?}-{:?}", first_number, last_number);          

          //1. Get ids
          let t2 = Instant::now();
          let mut inscription_ids: Vec<InscriptionId> = Vec::new();
          for j in needed_numbers.clone() {
            let inscription_entry = cloned_index.get_inscription_entry_by_sequence_number(j.try_into().unwrap()).unwrap();
            match inscription_entry {
              Some(inscription_entry) => {
                inscription_ids.push(inscription_entry.id);
              },
              None => {
                log::info!("No inscription found for sequence number: {}. Marking as not found. Breaking from loop, sleeping a minute", j);
                last_number = j;
                let status_vector = cloned_status_vector.clone();
                let mut locked_status_vector = status_vector.lock().await;
                for l in needed_numbers.clone() {                  
                  let status = locked_status_vector.iter_mut().find(|x| x.sequence_number == l).unwrap();
                  if l >= j {
                    status.status = "NOT_FOUND_LOCKED".to_string();
                  }                
                }
                should_sleep = true;
                break;
              }
            }
          }
          
          //2. Get inscriptions
          let t3 = Instant::now();
          let cloned_ids = inscription_ids.clone();
          let txs = cloned_index.get_transactions(cloned_ids.into_iter().map(|x| x.txid).collect());
          let err_txs = match txs {
              Ok(txs) => Some(txs),
              Err(error) => {
                println!("Error getting transactions {}-{}: {:?}", first_number, last_number, error);
                let status_vector = cloned_status_vector.clone();
                { //Enclosing braces to drop the mutex so sleep doesn't block
                  let mut locked_status_vector = status_vector.lock().await;
                  for j in needed_numbers.clone() {                  
                    let status = locked_status_vector.iter_mut().find(|x| x.sequence_number == j).unwrap();
                    status.status = "ERROR".to_string();
                  }
                }
                println!("error string: {}", error.to_string());
                if  error.to_string().contains("Failed to fetch raw transaction") || 
                    error.to_string().contains("connection closed") || 
                    error.to_string().contains("error trying to connect") || 
                    error.to_string().contains("end of file") {
                  println!("Pausing for 60s & Breaking from loop");
                  //std::mem::drop(locked_status_vector); //Drop the mutex so sleep doesn't block
                  tokio::time::sleep(Duration::from_secs(60)).await;
                }
                return;
              }
          };
          let clean_txs = err_txs.unwrap();
          let cloned_ids = inscription_ids.clone();
          let id_txs: Vec<_> = cloned_ids.into_iter().zip(clean_txs.into_iter()).collect();
          let mut inscriptions: Vec<Inscription> = Vec::new();
          for (inscription_id, tx) in id_txs {
            let inscription = ParsedEnvelope::from_transaction(&tx)
              .into_iter()
              .nth(inscription_id.index as usize)
              .map(|envelope| envelope.payload)
              .unwrap();
            inscriptions.push(inscription);
          }

          //3. Upload ordinal content to s3 (optional)
          let t4 = Instant::now();
          let cloned_ids = inscription_ids.clone();
          let cloned_inscriptions = inscriptions.clone();
          let number_id_inscriptions: Vec<_> = needed_numbers.clone().into_iter()
            .zip(cloned_ids.into_iter())
            .zip(cloned_inscriptions.into_iter())
            .map(|((x, y), z)| (x, y, z))
            .collect();          
          for (number, inscription_id, inscription) in number_id_inscriptions.clone() {
            if number < s3_upload_start_number {
                continue;
            }
            Self::upload_ordinal_content(&cloned_s3client, &cloned_bucket_name, inscription_id, inscription, s3_head_check).await;	//TODO: Handle errors
          }
          
          //4. Get ordinal metadata
          let t5 = Instant::now();
          let status_vector = cloned_status_vector.clone();

          let mut retrieval = Duration::from_millis(0);
          let mut metadata_vec: Vec<Metadata> = Vec::new();
          let mut sat_metadata_vec: Vec<SatMetadata> = Vec::new();
          for (number, inscription_id, inscription) in number_id_inscriptions {
            let t0 = Instant::now();
            let (metadata, sat_metadata) =  match Self::extract_ordinal_metadata(cloned_index.clone(), inscription_id, inscription.clone()) {
                Ok((metadata, sat_metadata)) => (metadata, sat_metadata),
                Err(error) => {
                  println!("Error: {} extracting metadata for sequence number: {}. Marking as error, will retry", error, number);
                  let mut locked_status_vector = status_vector.lock().await;
                  let status = locked_status_vector.iter_mut().find(|x| x.sequence_number == number).unwrap();
                  status.status = "ERROR_LOCKED".to_string();
                  continue;
                }
            };
            metadata_vec.push(metadata);            
            match sat_metadata {
              Some(sat_metadata) => {
                sat_metadata_vec.push(sat_metadata);
              },
              None => {}                
            }
            let t1 = Instant::now();            
            retrieval += t1.duration_since(t0);
          }

          //4.1 Insert metadata
          let mut client = match cloned_deadpool.get().await {
            Ok(client) => client,
            Err(err) => {
              log::info!("Error getting db client: {:?}, waiting a minute", err);
              let mut locked_status_vector = status_vector.lock().await;
              for j in needed_numbers.clone() {              
                let status = locked_status_vector.iter_mut().find(|x| x.sequence_number == j).unwrap();
                status.status = "ERROR".to_string();
              }
              return;
            }
          };
          let tx = match client.transaction().await{
            Ok(tx) => tx,
            Err(err) => {
              log::info!("Error starting db transaction: {:?}, waiting a minute", err);
              let mut locked_status_vector = status_vector.lock().await;
              for j in needed_numbers.clone() {
                let status = locked_status_vector.iter_mut().find(|x| x.sequence_number == j).unwrap();
                status.status = "ERROR".to_string();
              }
              return;
            }
          };
          let t51 = Instant::now();
          let insert_result = Self::bulk_insert_metadata(&tx, metadata_vec.clone()).await;
          let edition_result = Self::bulk_insert_editions(&tx, metadata_vec).await;
          let t51a = Instant::now();
          let sat_insert_result = Self::bulk_insert_sat_metadata(&tx, sat_metadata_vec.clone()).await;
          let t51b = Instant::now();
          let mut satributes_vec = Vec::new();
          for sat_metadata in sat_metadata_vec.iter() {
            let sat = Sat(sat_metadata.sat as u64);
            for block_rarity in sat.block_rarities().iter() {
              let satribute = Satribute {
                sat: sat_metadata.sat,
                satribute: block_rarity.to_string()
              };
              satributes_vec.push(satribute);
            }
            let sat_rarity = sat.rarity();
            if sat_rarity != Rarity::Common {
              let rarity = Satribute {
                sat: sat_metadata.sat,
                satribute: sat_rarity.to_string()
              };
              satributes_vec.push(rarity);
            }
          }
          let satribute_insert_result = Self::bulk_insert_satributes(&tx, satributes_vec).await;
          let t51c = Instant::now();
          //4.2 Upload content to db
          let mut content_vec: Vec<ContentBlob> = Vec::new();
          for inscription in inscriptions {
            if let Some(content) = inscription.body() {
              let content_type = match inscription.content_type() {
                  Some(content_type) => content_type,
                  None => ""
              };
              let content_encoding = inscription.content_encoding().map(|x| x.to_str().ok().map(|s| s.to_string())).flatten();
              let sha256 = digest(content);
              let content_blob = ContentBlob {
                sha256: sha256.to_string(),
                content: content.to_vec(),
                content_type: content_type.to_string(),
                content_encoding: content_encoding
              };
              content_vec.push(content_blob);
            }
          }
          let numbers_content = needed_numbers.clone()
            .into_iter()
            .zip(content_vec.into_iter())
            .map(|(x, y)| (x as i64, y))
            .collect::<Vec<_>>();
          let content_result = Self::bulk_insert_content(&tx, numbers_content).await;
          let commit_result = tx.commit().await;
          //4.3 Update status
          let t52 = Instant::now();
          if insert_result.is_err() || sat_insert_result.is_err() || content_result.is_err() || satribute_insert_result.is_err() || commit_result.is_err() || edition_result.is_err() {
            log::info!("Error bulk inserting into db for sequence numbers: {}-{}. Will retry after 60s", first_number, last_number);
            if insert_result.is_err() {
              log::info!("Metadata Error: {:?}", insert_result.unwrap_err());
            }
            if sat_insert_result.is_err() {
              log::info!("Sat Error: {:?}", sat_insert_result.unwrap_err());
            }
            if satribute_insert_result.is_err() {
              log::info!("Satribute Error: {:?}", satribute_insert_result.unwrap_err());
            }
            if content_result.is_err() {
              log::info!("Content Error: {:?}", content_result.unwrap_err());
            }
            if commit_result.is_err() {
              log::info!("Commit Error: {:?}", commit_result.unwrap_err());
            }
            if edition_result.is_err() {
              log::info!("Edition Error: {:?}", edition_result.unwrap_err());
            }
            should_sleep = true;
            let mut locked_status_vector = status_vector.lock().await;
            for j in needed_numbers.clone() {              
              let status = locked_status_vector.iter_mut().find(|x| x.sequence_number == j).unwrap();
              status.status = "ERROR".to_string();
            }
          } else {
            let mut locked_status_vector = status_vector.lock().await;
            for j in needed_numbers.clone() {              
              let status = locked_status_vector.iter_mut().find(|x| x.sequence_number == j).unwrap();
              //_LOCKED state to prevent other threads from changing status before current thread completes
              if status.status != "NOT_FOUND_LOCKED" && status.status != "ERROR_LOCKED" {
                status.status = "SUCCESS".to_string();
              } else if status.status == "NOT_FOUND_LOCKED" {
                status.status = "NOT_FOUND".to_string();
              } else if status.status == "ERROR_LOCKED" {
                status.status = "ERROR".to_string();
              }
            }
          }
          
          //5. Log timings
          let t6 = Instant::now();
          if first_number != last_number {
            log::info!("Finished numbers {} - {}", first_number, last_number);
          }
          let timing = IndexerTimings {
            inscription_start: first_number,
            inscription_end: last_number + 1,
            acquire_permit_start: t0,
            acquire_permit_end: t1,
            get_numbers_start: t1,
            get_numbers_end: t2,
            get_id_start: t2,
            get_id_end: t3,
            get_inscription_start: t3,
            get_inscription_end: t4,
            upload_content_start: t4,
            upload_content_end: t5,
            get_metadata_start: t5,
            get_metadata_end: t6,
            retrieval: retrieval,
            insertion: t52.duration_since(t51),
            metadata_insertion: t51a.duration_since(t51),
            sat_insertion: t51b.duration_since(t51a),
            edition_insertion: t51c.duration_since(t51b),
            content_insertion: t52.duration_since(t51c),
            locking: t6.duration_since(t52)
          };
          cloned_timing_vector.lock().await.push(timing);
          Self::print_index_timings(cloned_timing_vector, n_threads as u32).await;

          //6. Sleep thread if up to date.
          if should_sleep {
            tokio::time::sleep(Duration::from_secs(60)).await;
          }
        });        
        
      }
    })
  }

  pub(crate) fn run_address_indexer(self, settings: Settings, index: Arc<Index>) -> JoinHandle<()> {
    let address_indexer_thread = thread::spawn(move ||{
      let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
      rt.block_on(async move {
        let deadpool = match Self::get_deadpool(settings.clone()).await {
          Ok(deadpool) => deadpool,
          Err(err) => {
            println!("Error creating deadpool: {:?}", err);
            return;
          }
        };
        let create_tranfer_result = Self::create_transfers_table(deadpool.clone()).await;
        let create_address_result = Self::create_address_table(deadpool.clone()).await;
        let create_blockstats_result = Self::create_blockstats_table(deadpool.clone()).await;
        let create_inscription_blockstats_result = Self::create_inscription_blockstats_table(deadpool.clone()).await;
        if create_tranfer_result.is_err() {
          println!("Error creating db tables: {:?}", create_tranfer_result.unwrap_err());
          return;
        }
        if create_address_result.is_err() {
          println!("Error creating db tables: {:?}", create_address_result.unwrap_err());
          return;
        }
        if create_blockstats_result.is_err() {
          println!("Error creating db tables: {:?}", create_blockstats_result.unwrap_err());
          return;
        }
        if create_inscription_blockstats_result.is_err() {
          println!("Error creating db tables: {:?}", create_inscription_blockstats_result.unwrap_err());
          return;
        }

        let fetcher = fetcher::Fetcher::new(&settings).unwrap();
        let first_inscription_height = settings.first_inscription_height();
        let mut height = match Self::get_start_block(deadpool.clone()).await {
          Ok(height) => height,
          Err(err) => {
            log::info!("Error getting start block from db: {:?}, waiting a minute", err);
            return;
          }
        };
        log::info!("Address indexing block start height: {:?}", height);
        let mut blockstats = Vec::new();
        loop {
          let t0 = Instant::now();
          // break if ctrl-c is received
          if SHUTTING_DOWN.load(atomic::Ordering::Relaxed) {
            break;
          }

          // make sure block is indexed before requesting transfers
          let indexed_height = index.get_blocks_indexed().unwrap();
          if height > indexed_height {
            log::info!("Requesting block transfers for block: {:?}, only indexed up to: {:?}. Waiting a minute", height, indexed_height);
            tokio::time::sleep(Duration::from_secs(60)).await;
            continue;
          }

          let blockstat_result = match index.get_block_stats(height as u64) {
            Ok(blockstats) => blockstats,
            Err(err) => {
              log::info!("Error getting block stats for block height: {:?} - {:?}, waiting a minute", height, err);
              tokio::time::sleep(Duration::from_secs(60)).await;
              continue;
            }
          };

          let block_size_result = match index.get_block_size(height) {
            Ok(block_size) => block_size,
            Err(err) => {
              log::info!("Error getting block size for block height: {:?} - {:?}, waiting a minute", height, err);
              tokio::time::sleep(Duration::from_secs(60)).await;
              continue;
            }
          };
          let blockstat = BlockStats {
            block_number: height as i64,
            block_timestamp: blockstat_result.clone().map(|x| x.time.map(|y| 1000*y as i64)).flatten(), //Convert to millis
            block_tx_count: blockstat_result.clone().map(|x| x.txs.map(|y| y as i64)).flatten(),
            block_size: Some(block_size_result as i64),
            block_fees: blockstat_result.clone().map(|x| x.total_fee.map(|y| y.to_sat() as i64)).flatten(),
            min_fee: blockstat_result.clone().map(|x| x.min_fee_rate.map(|y| y.to_sat() as i64)).flatten(),
            max_fee: blockstat_result.clone().map(|x| x.max_fee_rate.map(|y| y.to_sat() as i64)).flatten(),
            average_fee: blockstat_result.clone().map(|x| x.fee_rate_percentiles.map(|y| y.fr_50th.to_sat() as i64)).flatten(),
            //average_fee: blockstat_result.clone().map(|x| x.avg_fee_rate.map(|y| y.to_sat() as i64)).flatten()
          };
          blockstats.push(blockstat);

          let mut conn = match deadpool.get().await {
            Ok(conn) => conn,
            Err(err) => {
              log::info!("Error getting db connection: {:?}, waiting a minute", err);
              tokio::time::sleep(Duration::from_secs(60)).await;
              continue;
            }
          };
          let deadpool_tx = match conn.transaction().await {
            Ok(tx) => tx,
            Err(err) => {
              log::info!("Error starting db transaction: {:?}, waiting a minute", err);
              tokio::time::sleep(Duration::from_secs(60)).await;
              continue;
            }
          };

          if height < first_inscription_height {
            if height % 100000 == 0 {
              log::info!("Inserting blockstats @ {}", height);
              let insert = Self::bulk_insert_blockstats(&deadpool_tx, blockstats.clone()).await;
              let commit = deadpool_tx.commit().await;
              if insert.is_err() || commit.is_err() {
                if insert.is_err() {
                  log::info!("Error inserting blockstats into db: {:?}, waiting a minute", insert.unwrap_err());
                }
                if commit.is_err() {
                  log::info!("Error committing blockstats into db: {:?}, waiting a minute", commit.unwrap_err());
                }
                tokio::time::sleep(Duration::from_secs(60)).await;
                continue;
              } else {
                blockstats = Vec::new();
              }
            }
            height += 1;
            continue;
          } else {
            match Self::bulk_insert_blockstats(&deadpool_tx, blockstats.clone()).await {
              Ok(_) => {
                log::debug!("Inserted blockstats @ {}", height);
                blockstats = Vec::new();
              },
              Err(err) => {
                log::info!("Error inserting blockstats into db: {:?}, waiting a minute", err);
                tokio::time::sleep(Duration::from_secs(60)).await;
                continue;
              }
            }
          }

          let t1 = Instant::now();
          let transfers = match index.get_transfers_by_block_height(height) {
            Ok(transfers) => transfers,
            Err(err) => {
              log::info!("Error getting transfers for block height: {:?} - {:?}, waiting a minute", height, err);
              tokio::time::sleep(Duration::from_secs(60)).await;
              continue;
            }
          };
          
          if transfers.len() == 0 {
            log::debug!("No transfers found for block height: {:?}, skipping", height);
            let insert_inscription_blockstats_result = Self::bulk_insert_inscription_blockstats(&deadpool_tx, height as i64).await;
            let commit_result = deadpool_tx.commit().await;
            if commit_result.is_err() || insert_inscription_blockstats_result.is_err() {
              if insert_inscription_blockstats_result.is_err() {
                log::info!("Error inserting inscription blockstats into db: {:?}, waiting a minute", insert_inscription_blockstats_result.unwrap_err());
              }
              if commit_result.is_err() {
                log::info!("Error committing inscription blockstats into db: {:?}, waiting a minute", commit_result.unwrap_err());
              }
              tokio::time::sleep(Duration::from_secs(60)).await;
              continue;              
            }
            height += 1;
            continue;
          }
          let t2 = Instant::now();
          let mut tx_id_list = transfers.clone().into_iter().map(|(_id, _tx_offset, _,satpoint)| satpoint.outpoint.txid).collect::<Vec<_>>();
          let transfer_counts: HashMap<Txid, u64> = tx_id_list.iter().fold(HashMap::new(), |mut acc, &x| {
            *acc.entry(x).or_insert(0) += 1;
            acc
          });
          let mut prev_tx_id_list = transfers.clone().into_iter().map(|(_id, _tx_offset, previous_satpoint,_)| previous_satpoint.outpoint.txid).collect::<Vec<_>>();
          tx_id_list.append(&mut prev_tx_id_list);
          tx_id_list.retain(|x| *x != Hash::all_zeros());
          let tx_id_list: Vec<Txid> = tx_id_list.into_iter().unique().collect();
          
          let txs = match fetcher.get_transactions(tx_id_list.clone()).await {
            Ok(txs) => {
              txs.into_iter().map(|tx| Some(tx)).collect::<Vec<_>>()
            }
            Err(e) => {
              log::info!("Error getting transfer transactions for block height: {:?} - {:?}", height, e);
              if e.to_string().contains("No such mempool or blockchain transaction") || e.to_string().contains("Broken pipe") || e.to_string().contains("end of file") || e.to_string().contains("EOF while parsing") {
                log::info!("Attempting 1 at a time");
                let mut txs = Vec::new();
                for tx_id in tx_id_list {
                  if tx_id == Hash::all_zeros() {
                    continue;
                  };
                  let tx = match fetcher.get_transactions(vec![tx_id]).await {
                    Ok(mut tx) => Some(tx.pop().unwrap()),
                    Err(e) => {                      
                      log::error!("ERROR: skipped non-miner transfer: {:?} - {:?}, trying again in a minute", tx_id, e);
                      tokio::time::sleep(Duration::from_secs(60)).await;
                      continue;
                    }
                  };
                  txs.push(tx);
                }
                txs
              } else {
                log::info!("Unknown Error getting transfer transactions for block height: {:?} - {:?} - Waiting a minute", height, e);
                tokio::time::sleep(Duration::from_secs(60)).await;
                continue;
              }              
            }
          };

          let mut tx_map: HashMap<Txid, Transaction> = HashMap::new();
          for tx in txs {
            if let Some(tx) = tx {
              tx_map.insert(tx.txid(), tx);   
            }
          }

          let t3 = Instant::now();          
          let mut seq_point_transfer_details = Vec::new();
          let mut error_in_loop = false;
          for (sequence_number, tx_offset, old_satpoint, satpoint) in transfers {
            //1. Get ordinal receive address
            let (address, prev_address, price, tx_fee, tx_size) = if satpoint.outpoint == unbound_outpoint() && (old_satpoint.outpoint == unbound_outpoint() || old_satpoint.outpoint.is_null()) {
              ("unbound".to_string(), "unbound".to_string(), 0, 0, 0)
            } else if satpoint.outpoint == unbound_outpoint() {
              let prev_tx = tx_map.get(&old_satpoint.outpoint.txid).unwrap();
              let prev_output = prev_tx
                .clone()
                .output
                .into_iter()
                .nth(old_satpoint.outpoint.vout.try_into().unwrap())
                .unwrap();
              let prev_address = settings
                .chain()
                .address_from_script(&prev_output.script_pubkey)
                .map(|address| address.to_string())
                .unwrap_or_else(|e| e.to_string());
              ("unbound".to_string(), prev_address, 0, 0, 0)
            } else if old_satpoint.outpoint == unbound_outpoint() || old_satpoint.outpoint.is_null() {
              let tx = tx_map.get(&satpoint.outpoint.txid).unwrap();
              //1. Get address
              let output = tx
                .clone()
                .output
                .into_iter()
                .nth(satpoint.outpoint.vout.try_into().unwrap())
                .unwrap();
              let address = settings
                .chain()
                .address_from_script(&output.script_pubkey)
                .map(|address| address.to_string())
                .unwrap_or_else(|e| e.to_string());
              //2. Get fee
              let tx_fee = match index.get_tx_fee(satpoint.outpoint.txid) {
                Ok(tx_fee) => tx_fee,
                Err(e) => {
                  log::info!("Error getting tx fee for {:?} - {:?} breaking and waiting a minute", satpoint.outpoint.txid, e);
                  error_in_loop = true;
                  break;
                }
              };
              //3. Get size
              let tx_size = tx.vsize();
              //4. Get transfer count
              let transfer_count = transfer_counts.get(&satpoint.outpoint.txid).unwrap();

              (address, "unbound".to_string(), 0, tx_fee/transfer_count, (tx_size as u64)/transfer_count)
            } else {
              let tx = tx_map.get(&satpoint.outpoint.txid).unwrap();
              let prev_tx = tx_map.get(&old_satpoint.outpoint.txid).unwrap();
              //1a. Get address
              let output = tx
                .clone()
                .output
                .into_iter()
                .nth(satpoint.outpoint.vout.try_into().unwrap())
                .unwrap();
              let address = settings
                .chain()
                .address_from_script(&output.script_pubkey)
                .map(|address| address.to_string())
                .unwrap_or_else(|e| e.to_string());
              //1b. Get previous address
              let prev_output = prev_tx
                .clone()
                .output
                .into_iter()
                .nth(old_satpoint.outpoint.vout.try_into().unwrap())
                .unwrap();
              let prev_address = settings
                .chain()
                .address_from_script(&prev_output.script_pubkey)
                .map(|address| address.to_string())
                .unwrap_or_else(|e| e.to_string());

              //2. Get price
              let mut price = 0;
              for (input_index, txin) in tx.input.iter().enumerate() {
                if txin.previous_output == old_satpoint.outpoint {
                  let first_script_instruction = txin.script_sig.instructions().next();
                  let last_sig_byte = match first_script_instruction {
                    Some(first_script_instruction) => {
                      match first_script_instruction.clone() {
                        Ok(first_script_instruction) => {
                          let last_sig_byte = first_script_instruction.push_bytes().map(|x| x.as_bytes().last()).flatten().cloned();
                          last_sig_byte
                        },
                        Err(_) => None
                      }
                    },
                    None => {
                      match txin.witness.nth(0) {
                        Some(witness_element_bytes) => witness_element_bytes.last().cloned(),
                        None => None
                      }
                    }
                  };
                  price = match last_sig_byte {
                    Some(last_sig_byte) => {                      
                      // IF SIG_SINGLE|ANYONECANPAY (0x83), Then price is on same output index as the ordinal's input index
                      if last_sig_byte == 0x83 {
                        price = match tx.output.clone().into_iter().nth(input_index) {
                          Some(output) => {
                            //Check previous tx value to see if it's splitting off an ordinal within a large UTXO
                            let prev_tx_value = prev_tx.output.clone().into_iter().nth(old_satpoint.outpoint.vout.try_into().unwrap()).unwrap().value;
                            if prev_tx_value > 20000 {
                              0
                            } else {
                              output.value
                            }
                          },
                          None => 0
                        };
                      }
                      // This gives shoddy data - ignore for now
                      // IF SIG_ALL (0x01), Then price is on second output index (for offers)
                      // } else if last_sig_byte == &0x01 {
                      //   price = match tx.output.clone().into_iter().nth(1) {
                      //     Some(output) => output.value,
                      //     None => 0
                      //   };
                      // }
                      price
                    },
                    None => 0
                  };
                }
              }
              
              //3. Get fee
              let tx_fee = match index.get_tx_fee(satpoint.outpoint.txid) {
                Ok(tx_fee) => tx_fee,
                Err(e) => {
                  log::info!("Error getting tx fee for {:?} - {:?} breaking and waiting a minute", satpoint.outpoint.txid, e);
                  error_in_loop = true;
                  break;
                }
              };

              //4. Get size
              let tx_size = tx.vsize();
              //5. Get transfer count
              let transfer_count = transfer_counts.get(&satpoint.outpoint.txid).unwrap();

              (address, prev_address, price, tx_fee/transfer_count, (tx_size as u64)/transfer_count)
            };
            seq_point_transfer_details.push((sequence_number, tx_offset, satpoint, address, prev_address, price, tx_fee, tx_size));
          }
          if error_in_loop {
            log::info!("Error detected tx loop for block {:?}, breaking and waiting a minute", height);
            tokio::time::sleep(Duration::from_secs(60)).await;
            continue;
          }

          let t4 = Instant::now();
          let block_time = index.block_time(Height(height)).unwrap();
          let mut transfer_vec = Vec::new();
          for (sequence_number, tx_offset, point, address, prev_address, price, tx_fee, tx_size) in seq_point_transfer_details {
            let entry = index.get_inscription_entry_by_sequence_number(sequence_number).unwrap();
            let id = entry.unwrap().id;
            let transfer = Transfer {
              id: id.to_string(),
              block_number: height.try_into().unwrap(),
              block_timestamp: block_time.timestamp().timestamp_millis(),
              satpoint: point.to_string(),
              tx_offset: tx_offset as i64,
              transaction: point.outpoint.txid.to_string(),
              vout: point.outpoint.vout as i32,
              offset: point.offset as i64,
              address: address,
              previous_address: prev_address,
              price: price as i64,
              tx_fee: tx_fee as i64,
              tx_size: tx_size as i64,
              is_genesis: point.outpoint.txid == id.txid
            };
            transfer_vec.push(transfer);
          }
          let t5 = Instant::now();
          let insert_transfer_result = Self::bulk_insert_transfers(&deadpool_tx, transfer_vec.clone()).await;
          let t6 = Instant::now();
          let insert_address_result = Self::bulk_insert_addresses(&deadpool_tx, transfer_vec).await;
          let insert_inscription_blockstats_result = Self::bulk_insert_inscription_blockstats(&deadpool_tx, height as i64).await;
          let commit_result = deadpool_tx.commit().await;
          if insert_transfer_result.is_err() || insert_address_result.is_err() || insert_inscription_blockstats_result.is_err() || commit_result.is_err() {
            log::info!("Error bulk inserting addresses into db for block height: {:?}, waiting a minute", height);
            if insert_transfer_result.is_err() {
              log::info!("Transfer Error: {:?}", insert_transfer_result.unwrap_err());
            }
            if insert_address_result.is_err() {
              log::info!("Address Error: {:?}", insert_address_result.unwrap_err());
            }
            if insert_inscription_blockstats_result.is_err() {
              log::info!("Inscription blockstat Error: {:?}", insert_inscription_blockstats_result.unwrap_err());
            }
            if commit_result.is_err() {
              log::info!("Commit Error: {:?}", commit_result.unwrap_err());
            }
            tokio::time::sleep(Duration::from_secs(60)).await;
            continue;              
          }
          let t7 = Instant::now();
          log::info!("Address indexer: Indexed block: {:?}", height);
          log::info!("Height check: {:?} - Get transfers: {:?} - Get txs: {:?} - Get addresses {:?} - Create Vec: {:?} - Insert transfers: {:?} - Insert addresses: {:?} TOTAL: {:?}", t1.duration_since(t0), t2.duration_since(t1), t3.duration_since(t2), t4.duration_since(t3), t5.duration_since(t4), t6.duration_since(t5), t7.duration_since(t6), t7.duration_since(t0));
          height += 1;
        }
        println!("Address indexer stopped");
      })
    });
    return address_indexer_thread;
  }

  pub(crate) fn run_vermilion_server(self, settings: Settings) -> JoinHandle<()> {
    let verm_server_thread = thread::spawn(move ||{
      let rt = Runtime::new().unwrap();
      rt.block_on(async move {
        let deadpool = match Self::get_deadpool(settings).await {
          Ok(deadpool) => deadpool,
          Err(err) => {
            println!("Error creating deadpool: {:?}", err);
            return;
          }
        };
        
        let server_config = ApiServerConfig {
          deadpool: deadpool
        };

        let session_config = SessionConfig::default()
          .with_cookie_path("/api/random_inscriptions")
          .with_table_name("sessions_table");
        let session_store = SessionStore::<SessionNullPool>::new(None, session_config).await.unwrap();

        let app = Router::new()
          .route("/random_inscriptions", get(Self::random_inscriptions))          
          .layer(SessionLayer::new(session_store))
          .route("/", get(Self::root))
          .route("/home", get(Self::home))
          .route("/inscription/:inscription_id", get(Self::inscription))
          .route("/inscription_number/:number", get(Self::inscription_number))
          .route("/inscription_sha256/:sha256", get(Self::inscription_sha256))
          .route("/inscription_metadata/:inscription_id", get(Self::inscription_metadata))
          .route("/inscription_metadata_number/:number", get(Self::inscription_metadata_number))
          .route("/inscription_edition/:inscription_id", get(Self::inscription_edition))
          .route("/inscription_edition_number/:number", get(Self::inscription_edition_number))
          .route("/inscription_editions_sha256/:sha256", get(Self::inscription_editions_sha256))          
          .route("/inscription_children/:inscription_id", get(Self::inscription_children))
          .route("/inscription_children_number/:number", get(Self::inscription_children_number))
          .route("/inscription_referenced_by/:inscription_id", get(Self::inscription_referenced_by))
          .route("/inscription_referenced_by_number/:number", get(Self::inscription_referenced_by_number))
          .route("/inscriptions_in_block/:block", get(Self::inscriptions_in_block))
          .route("/inscriptions", get(Self::inscriptions))
          .route("/random_inscription", get(Self::random_inscription))
          .route("/recent_inscriptions", get(Self::recent_inscriptions))
          .route("/inscription_last_transfer/:inscription_id", get(Self::inscription_last_transfer))
          .route("/inscription_last_transfer_number/:number", get(Self::inscription_last_transfer_number))
          .route("/inscription_transfers/:inscription_id", get(Self::inscription_transfers))
          .route("/inscription_transfers_number/:number", get(Self::inscription_transfers_number))
          .route("/inscriptions_in_address/:address", get(Self::inscriptions_in_address))
          .route("/inscriptions_on_sat/:sat", get(Self::inscriptions_on_sat))
          .route("/inscriptions_in_sat_block/:block", get(Self::inscriptions_in_sat_block))
          .route("/sat_metadata/:sat", get(Self::sat_metadata))
          .route("/satributes/:sat", get(Self::satributes))
          .route("/inscription_collection_data/:inscription_id", get(Self::inscription_collection_data))
          .route("/inscription_collection_data_number/:number", get(Self::inscription_collection_data_number))
          .route("/block_statistics/:block", get(Self::block_statistics))
          .route("/sat_block_statistics/:block", get(Self::sat_block_statistics))
          .route("/blocks", get(Self::blocks))
          .route("/collection_summary/:collection_symbol", get(Self::collection_summary))          
          .route("/collection_holders/:collection_symbol", get(Self::collection_holders))
          .route("/collections", get(Self::collections))
          .route("/inscriptions_in_collection/:collection_symbol", get(Self::inscriptions_in_collection))
          .route("/search/:search_by_query", get(Self::search_by_query))
          .route("/block_icon/:block", get(Self::block_icon))
          .route("/sat_block_icon/:block", get(Self::sat_block_icon))
          .layer(map_response(Self::set_header))
          .layer(
            TraceLayer::new_for_http()
              .make_span_with(DefaultMakeSpan::new().level(TraceLevel::INFO))
              .on_request(|req: &Request<Body>, _span: &Span| {
                tracing::event!(TraceLevel::INFO, "Started processing request {}", req.uri().path());
              })
              .on_response(|res: &Response<BoxBody>, latency: Duration, _span: &Span| {
                tracing::event!(TraceLevel::INFO, "Finished processing request latency={:?} status={:?}", latency, res.status());
              })
          )
          .layer(
            CorsLayer::new()
              .allow_methods([http::Method::GET])
              .allow_origin(Any),
          )
          .with_state(server_config);

        let addr = SocketAddr::from(([127, 0, 0, 1], self.api_http_port.unwrap_or(81)));
        //tracing::debug!("listening on {}", addr);
        axum::Server::bind(&addr)
            .serve(app.into_make_service())
            .with_graceful_shutdown(Self::shutdown_signal())
            .await
            .unwrap();
      });
      println!("Vermilion server stopped");
    });
    return verm_server_thread;
  }

  pub(crate) fn run_ordinals_server(self, settings: Settings, index: Arc<Index>, handle: Handle) -> JoinHandle<()> {
    //1. Ordinals Server
    let server = server::Server {
      address: self.address,
      acme_domain: self.acme_domain,
      http_port: self.http_port,
      https_port: self.https_port,
      acme_cache: self.acme_cache,
      acme_contact: self.acme_contact,
      http: self.http,
      https: self.https,
      redirect_http_to_https: self.redirect_http_to_https,
      disable_json_api: self.disable_json_api,
      csp_origin: self.csp_origin,
      decompress: self.decompress,
      no_sync: self.no_sync,
      content_proxy: self.content_proxy,
      polling_interval: self.polling_interval,
    };
    let server_thread = thread::spawn(move || {
      let server_result = server.run(settings, index, handle);
      match server_result {
        Ok(_) => {
          println!("Ordinals server stopped");
        },
        Err(err) => {
          println!("Ordinals server failed to start: {:?}", err);
        }
      }
    });
    return server_thread;
  }

  pub(crate) fn run_migration_script(self, settings: Settings, index: Arc<Index>) -> JoinHandle<()> {
      let migration_thread = thread::spawn(move || {
        if self.run_migration_script {
          println!("Migration Script Starting");
          let migrator = Migrator {
            script_number: 1
          };
          let migration_result = migrator.run(settings, index);
          match migration_result {
            Ok(_) => {
              println!("Migration script stopped");
            },
            Err(err) => {
              println!("Migration script failed: {:?}", err);
            }
          }
        }
      });
      return migration_thread;
  }
  
  //Inscription Indexer Helper functions
  pub(crate) async fn upload_ordinal_content(client: &s3::Client, bucket_name: &str, inscription_id: InscriptionId, inscription: Inscription, head_check: bool) {
    let id = inscription_id.to_string();	
    let key = format!("content/{}", id);
    if head_check {
      let head_status = client	
        .head_object()	
        .bucket(bucket_name)	
        .key(key.clone())	
        .send()	
        .await;
      match head_status {	
        Ok(_) => {	
          log::debug!("Ordinal content already exists in S3: {}", id.clone());	
          return;	
        }	
        Err(error) => {	
          if error.to_string() == "service error" {
            let service_error = error.into_service_error();
            if service_error.to_string() != "NotFound" {
              println!("Error checking if ordinal {} exists in S3: {} - {:?} code: {:?}", id.clone(), service_error, service_error.message(), service_error.code());	
              return;	//error
            } else {
              log::trace!("Ordinal {} not found in S3, uploading", id.clone());
            }
          } else {
            println!("Error checking if ordinal {} exists in S3: {} - {:?}", id.clone(), error, error.message());	
            return; //error
          }
        }
      };
    }
    
    let body = Inscription::body(&inscription);	
    let bytes = match body {	
      Some(body) => body.to_vec(),	
      None => {	
        log::debug!("No body found for inscription: {}, filling with empty body", inscription_id);	
        Vec::new()	
      }	
    };	
    let content_type = match Inscription::content_type(&inscription) {	
      Some(content_type) => content_type,	
      None => {	
        log::debug!("No content type found for inscription: {}, filling with empty content type", inscription_id);	
        ""	
      }	
    };
    let put_status = client	
      .put_object()	
      .bucket(bucket_name)	
      .key(key)	
      .body(ByteStream::from(bytes))	
      .content_type(content_type)	
      .send()	
      .await;

    let _ret = match put_status {	
      Ok(put_status) => {	
        log::debug!("Uploaded ordinal content to S3: {}", id.clone());	
        put_status	
      }	
      Err(error) => {	
        log::error!("Error uploading ordinal {} to S3: {} - {:?}", id.clone(), error, error.message());	
        return;	
      }	
    };
  }

  fn is_bitmap_style(input: &str) -> bool {
    let pattern = r"^[^ \n]+[.][^ \n]+$";
    let re = regex::Regex::new(pattern).unwrap();
    re.is_match(input)
  }
  
  fn is_recursive(input: &str) -> bool {
    input.contains("/content")
  }

  fn is_maybe_json(input: &str, content_type: Option<String>) -> bool { 
    let length = input.len();
    if length < 2 {
      return false; // The string is too short
    }
    if content_type.is_some() {
      let content_type = content_type.unwrap();
      if !(content_type.contains("json") || content_type.contains("text/plain")) {
        return false; // The content type is not a text type, don't check for html/svg false positives
      }
    }
    let num_colons = input.chars().filter(|&c| c == ':').count();
    let num_quotes = input.chars().filter(|&c| c == '"').count();
    let num_commas = input.chars().filter(|&c| c == ',').count();
    let ratio = (num_colons as f32 + num_quotes as f32 + num_commas as f32)/ length as f32;
    let first_char = input.chars().next().unwrap();
    let last_char = input.chars().last().unwrap();  
    first_char == '{' || last_char == '}' || ratio > 0.1
  }

  fn cbor_into_string(cbor: CborValue) -> Option<String> {
    match cbor {
        CborValue::Text(string) => Some(string),
        _ => None,
    }
  }

  fn cbor_to_json(cbor: CborValue) -> JsonValue {
    match cbor {
        CborValue::Null => JsonValue::Null,
        CborValue::Bool(boolean) => JsonValue::Bool(boolean),
        CborValue::Text(string) => JsonValue::String(string),
        CborValue::Integer(int) => JsonValue::Number({
            let int: i128 = int.into();
            if let Ok(int) = u64::try_from(int) {
                JsonNumber::from(int)
            } else if let Ok(int) = i64::try_from(int) {
                JsonNumber::from(int)
            } else {
                JsonNumber::from_f64(int as f64).unwrap()
            }
        }),
        CborValue::Float(float) => JsonValue::Number(JsonNumber::from_f64(float).unwrap()),
        CborValue::Array(vec) => JsonValue::Array(vec.into_iter().map(Self::cbor_to_json).collect()),
        CborValue::Map(map) => JsonValue::Object(map.into_iter().map(|(k, v)| (Self::cbor_into_string(k).unwrap(), Self::cbor_to_json(v))).collect()),
        CborValue::Bytes(bytes) => JsonValue::String(BASE64.encode(bytes)),
        CborValue::Tag(_tag, _value) => JsonValue::Null,
        _ => JsonValue::Null,
    }
  }

  pub(crate) fn extract_ordinal_metadata(index: Arc<Index>, inscription_id: InscriptionId, inscription: Inscription) -> Result<(Metadata, Option<SatMetadata>)> {
    let t0 = Instant::now();
    let entry = index
      .get_inscription_entry(inscription_id)
      .unwrap()
      .unwrap();
    let t1 = Instant::now();
    let content_length = match inscription.content_length() {
      Some(content_length) => Some(content_length as i64),
      None => {
        log::debug!("No content length found for inscription: {}, filling with 0", inscription_id);
        Some(0)
      }
    };
    let content_encoding = match inscription.content_encoding() {
      Some(content_encoding) => {
        match content_encoding.to_str() {
          Ok(content_encoding) => Some(content_encoding.to_string()),
          Err(_) => None
        }
      },
      None => None
    };
    let sat = match entry.sat {
      Some(sat) => Some(sat.n() as i64),
      None => {
        None
      }
    };
    let sat_block = match entry.sat {
      Some(sat) => Some(sat.height().0 as i64),
      None => {
        None
      }
    };
    let satributes = match entry.sat {
      Some(sat) => {
        let mut satributes = sat.block_rarities().iter().map(|x| x.to_string()).collect::<Vec<String>>();
        let sat_rarity = sat.rarity();
        if sat_rarity != Rarity::Common {
          satributes.push(sat_rarity.to_string()); 
        }
        satributes
      },
      None => Vec::new()
    };
    let mut parents = Vec::new();
    for parent in entry.parents {
      let parent_entry = index
        .get_inscription_entry_by_sequence_number(parent)?
        .ok_or(anyhow!("Parent not found"))?
        .id
        .to_string();
      parents.push(parent_entry);
    }
    let metaprotocol = inscription.metaprotocol().map_or(None, |str| Some(str.to_string()));
    if let Some(metaprotocol_inner) = metaprotocol.clone() {
      if metaprotocol_inner.len() > 100 {
        log::warn!("Metaprotocol too long: {} - {}, truncating", inscription_id, metaprotocol_inner);
        //metaprotocol_inner.truncate(100);
        //metaprotocol = Some(metaprotocol_inner);
      }
    }
    let on_chain_metadata = inscription.metadata().map_or(serde_json::Value::Null, |cbor| Self::cbor_to_json(cbor));
    let sha256 = match inscription.body() {
      Some(body) => {
        let hash = digest(body);
        Some(hash)
      },
      None => {
        None
      }
    };
    let text = match inscription.body() {
      Some(body) => {
        let text = String::from_utf8(body.to_vec());
        match text {
          Ok(text) => Some(text),
          Err(_) => None
        }
      },
      None => {
        None
      }
    };
    let referenced_ids = match text.clone() {
      Some(text) => {
        let re = regex::Regex::new(r"content/([[:xdigit:]]{64}i\d+)").unwrap();
        let referenced_ids = re.captures_iter(&text).map(|x| x[1].to_string()).collect::<Vec<String>>();
        referenced_ids
      },
      None => Vec::new()
    };
    let is_json = match inscription.body() {
      Some(body) => {
        let json = serde_json::from_slice::<serde::de::IgnoredAny>(body);
        match json {
          Ok(_) => true,
          Err(_) => false
        }
      },
      None => {
        false
      }
    };
    let is_maybe_json = match text.clone() {
      Some(text) => Self::is_maybe_json(&text, inscription.content_type().map(str::to_string)),
      None => false
    };
    let is_bitmap_style = match text.clone() {
      Some(text) => Self::is_bitmap_style(&text),
      None => false
    };
    let is_recursive = match text.clone() {
      Some(text) => Self::is_recursive(&text),
      None => false
    };
    let content_category = match inscription.content_type() {
      Some(content_type) => {
        let content_type = content_type.to_string();
        let mut content_category = match content_type.as_str() {
          "text/plain;charset=utf-8" => "text", 
          "text/plain" => "text",
          "text/markdown" => "text",
          "text/javascript" => "javascript",
          "text/plain;charset=us-ascii" => "text",
          "text/rtf" => "text",
          "image/jpeg" => "image",
          "image/png" => "image",
          "image/svg+xml" => "image",
          "image/webp" => "image",
          "image/avif" => "image", 
          "image/tiff" => "image", 
          "image/heic" => "image", 
          "image/jp2" => "image",
          "image/gif" => "gif",
          "audio/mpeg" => "audio", 
          "audio/ogg" => "audio", 
          "audio/wav" => "audio", 
          "audio/webm" => "audio", 
          "audio/flac" => "audio", 
          "audio/mod" => "audio", 
          "audio/midi" => "audio", 
          "audio/x-m4a" => "audio",
          "video/mp4" => "video",
          "video/ogg" => "video",
          "video/webm" => "video",
          "text/html;charset=utf-8" => "html",
          "text/html" => "html",
          "model/gltf+json" => "3d",
          "model/gltf-binary" => "3d",
          "model/stl" => "3d",
          "application/json" => "json",
          "application/json;charset=utf-8" => "json",
          "application/pdf" => "pdf",
          "application/javascript" => "javascript",          
          _ => "unknown"
        };
        if is_json {
          content_category = "json";
        } else if is_maybe_json {
          content_category = "maybe_json";
        } else if is_bitmap_style {
          content_category = "namespace";
        }
        content_category
      },
      None => "unknown"
    };
    let charms = Charm::ALL
      .iter()
      .filter(|charm| charm.is_set(entry.charms))
      .map(|charm| charm.to_string())
      .collect();
    let metadata = Metadata {
      id: inscription_id.to_string(),
      content_length: content_length,
      content_encoding: content_encoding,
      content_type: inscription.content_type().map(str::to_string),
      content_category: content_category.to_string(),
      genesis_fee: entry.fee.try_into().unwrap(),
      genesis_height: entry.height.try_into().unwrap(),
      genesis_transaction: inscription_id.txid.to_string(),
      pointer: inscription.pointer().map(|value| { value.try_into().unwrap()}),
      number: entry.inscription_number as i64,
      sequence_number: entry.sequence_number as i64,
      parents: parents,
      delegate: inscription.delegate().map(|x| x.to_string()),
      metaprotocol: metaprotocol,
      on_chain_metadata: on_chain_metadata,
      sat: sat,
      sat_block: sat_block,
      satributes: satributes.clone(),
      charms: charms,
      timestamp: entry.timestamp.try_into().unwrap(),
      sha256: sha256.clone(),
      text: text,
      referenced_ids: referenced_ids,
      is_json: is_json,
      is_maybe_json: is_maybe_json,
      is_bitmap_style: is_bitmap_style,
      is_recursive: is_recursive
    };
    let t2 = Instant::now();
    let sat_metadata = match entry.sat {
      Some(sat) => {
        let sat_blocktime = index.block_time(sat.height())?;
        let sat_metadata = SatMetadata {
          sat: sat.0 as i64,
          satributes: satributes,
          decimal: sat.decimal().to_string(),
          degree: sat.degree().to_string(),
          name: sat.name(),
          block: sat.height().0 as i64,
          cycle: sat.cycle() as i64,
          epoch: sat.epoch().0 as i64,
          period: sat.period() as i64,
          third: sat.third() as i64,
          rarity: sat.rarity().to_string(),
          percentile: sat.percentile(),
          timestamp: sat_blocktime.timestamp().timestamp()
        };
        Some(sat_metadata)
      },
      None => None
    };
    let t3 = Instant::now();

    log::trace!("index: {:?} metadata: {:?} sat: {:?} total: {:?}", t1.duration_since(t0), t2.duration_since(t1), t3.duration_since(t2), t3.duration_since(t0));
    Ok((metadata, sat_metadata))
  }

  pub(crate) async fn initialize_db_tables(pool: deadpool_postgres::Pool) -> anyhow::Result<()> {
    Self::create_metadata_table(pool.clone()).await.context("Failed to create metadata table")?;
    Self::create_sat_table(pool.clone()).await.context("Failed to create sat table")?;
    Self::create_content_table(pool.clone()).await.context("Failed to create content table")?;
    Self::create_edition_table(pool.clone()).await.context("Failed to create editions table")?;
    Self::create_editions_total_table(pool.clone()).await.context("Failed to create editions total table")?;
    Self::create_delegate_table(pool.clone()).await.context("Failed to create delegate table")?;
    Self::create_delegates_total_table(pool.clone()).await.context("Failed to create delegates total table")?;
    Self::create_reference_table(pool.clone()).await.context("Failed to create reference table")?;
    Self::create_references_total_table(pool.clone()).await.context("Failed to create references total table")?;
    Self::create_inscription_satributes_table(pool.clone()).await.context("Failed to create inscription satributes table")?;
    Self::create_inscription_satributes_total_table(pool.clone()).await.context("Failed to create inscription satributes total table")?;
    Self::create_satributes_table(pool.clone()).await.context("Failed to create satributes table")?;
    Self::create_collection_list_table(pool.clone()).await.context("Failed to create collection list table")?;
    Self::create_collections_table(pool.clone()).await.context("Failed to create collections table")?;
    Self::create_collections_summary_table(pool.clone()).await.context("Failed to create collections summary table")?;
    
    Self::create_procedure_log(pool.clone()).await.context("Failed to create proc log")?;
    Self::create_collection_summary_procedure(pool.clone()).await.context("Failed to create collection summary proc")?;
    Self::create_edition_procedure(pool.clone()).await.context("Failed to create edition proc")?;
    Self::create_weights_procedure(pool.clone()).await.context("Failed to create weights proc")?;

    Self::create_edition_insert_trigger(pool.clone()).await.context("Failed to create edition trigger")?;
    Self::create_metadata_insert_trigger(pool.clone()).await.context("Failed to create metadata trigger")?;
    Self::create_transfer_insert_trigger(pool.clone()).await.context("Failed to create transfer trigger")?;

    Self::create_ordinals_full_view(pool.clone()).await.context("Failed to create ordinals full view")?;
    Ok(())
  }

  pub(crate) async fn create_metadata_table(pool: deadpool_postgres::Pool) -> anyhow::Result<()> {
    let conn = pool.get().await?;
    conn.simple_query(
      r"CREATE TABLE IF NOT EXISTS ordinals (
        sequence_number bigint not null primary key,
        id varchar(80) not null,
        content_length bigint,
        content_type text,
        content_encoding text,
        content_category varchar(20),
        genesis_fee bigint,
        genesis_height bigint,
        genesis_transaction varchar(80),
        pointer bigint,
        number bigint,          
        parents varchar(80)[],
        delegate varchar(80),
        metaprotocol text,
        on_chain_metadata jsonb,
        sat bigint,
        sat_block bigint,
        satributes varchar(30)[],
        charms varchar(15)[],
        timestamp bigint,
        sha256 varchar(64),
        text text,
        referenced_ids varchar(80)[],
        is_json boolean,
        is_maybe_json boolean,
        is_bitmap_style boolean,
        is_recursive boolean
      )").await?;
    conn.simple_query(r"
      CREATE INDEX IF NOT EXISTS index_metadata_id ON ordinals (id);
      CREATE INDEX IF NOT EXISTS index_metadata_number ON ordinals (number);
      CREATE INDEX IF NOT EXISTS index_metadata_block ON ordinals (genesis_height);
      CREATE INDEX IF NOT EXISTS index_metadata_sha256 ON ordinals (sha256);
      CREATE INDEX IF NOT EXISTS index_metadata_sat ON ordinals (sat);
      CREATE INDEX IF NOT EXISTS index_metadata_sat_block ON ordinals (sat_block);
      CREATE INDEX IF NOT EXISTS index_metadata_satributes on ordinals USING GIN (satributes);
      CREATE INDEX IF NOT EXISTS index_metadata_charms on ordinals USING GIN (charms);
      CREATE INDEX IF NOT EXISTS index_metadata_parents ON ordinals USING GIN (parents);
      CREATE INDEX IF NOT EXISTS index_metadata_delegate ON ordinals (delegate);
      CREATE INDEX IF NOT EXISTS index_metadata_fee ON ordinals (genesis_fee);
      CREATE INDEX IF NOT EXISTS index_metadata_size ON ordinals (content_length);
      CREATE INDEX IF NOT EXISTS index_metadata_type ON ordinals (content_type);
      CREATE INDEX IF NOT EXISTS index_metadata_category ON ordinals (content_category);
      CREATE INDEX IF NOT EXISTS index_metadata_metaprotocol ON ordinals (metaprotocol);
      CREATE INDEX IF NOT EXISTS index_metadata_text ON ordinals USING GIN (to_tsvector('english', left(text, 1048575)));
      CREATE INDEX IF NOT EXISTS index_metadata_referenced_ids ON ordinals USING GIN (referenced_ids);
    ").await?;
    conn.simple_query(r"
      CREATE INDEX IF NOT EXISTS index_metadata_sat_block_sat on ordinals (sat_block, sat);
      CREATE INDEX IF NOT EXISTS index_metadata_sat_block_sequence on ordinals (sat_block, sequence_number);
      CREATE INDEX IF NOT EXISTS index_metadata_sat_block_fee on ordinals (sat_block, genesis_fee);
      CREATE INDEX IF NOT EXISTS index_metadata_sat_block_size on ordinals (sat_block, content_length);
    ").await?;
    conn.simple_query(r"
      CREATE EXTENSION IF NOT EXISTS btree_gin;
      CREATE INDEX IF NOT EXISTS index_metadata_type_satribute on ordinals USING GIN(content_type, satributes);
      CREATE INDEX IF NOT EXISTS index_metadata_type_charm on ordinals USING GIN(content_type, charms);
      CREATE INDEX IF NOT EXISTS index_metadata_category_satribute on ordinals USING GIN(content_category, satributes);
      CREATE INDEX IF NOT EXISTS index_metadata_category_charm on ordinals USING GIN(content_category, charms);
      CREATE INDEX IF NOT EXISTS index_metadata_json on ordinals(is_json, is_maybe_json, is_bitmap_style);
    ").await?;
  
    Ok(())
  }
  
  pub(crate) async fn create_sat_table(pool: deadpool_postgres::Pool<>) -> anyhow::Result<()> {
    let conn = pool.get().await?;
    conn.simple_query(r"
      CREATE TABLE IF NOT EXISTS sat (
      sat bigint not null primary key,
      satributes varchar(30)[],
      sat_decimal text,
      degree text,
      name text,
      block bigint,
      cycle bigint,
      epoch bigint,
      period bigint,
      third bigint,
      rarity varchar(20),
      percentile text,
      timestamp bigint
      )").await?;
    conn.simple_query(r"
      CREATE INDEX IF NOT EXISTS index_sat_block ON sat (block);
      CREATE INDEX IF NOT EXISTS index_sat_rarity ON sat (rarity);
      ").await?;
    Ok(())
  }
  
  pub(crate) async fn create_content_table(pool: deadpool_postgres::Pool<>) -> anyhow::Result<()> {
    let conn = pool.get().await?;
    conn.simple_query(
      r"CREATE TABLE IF NOT EXISTS content (
        content_id bigint,
        sha256 varchar(64) NOT NULL PRIMARY KEY,
        content bytea,
        content_type text,
        content_encoding text
      )").await?;
    conn.simple_query(r"
      CREATE INDEX IF NOT EXISTS index_content_content_id ON content (content_id);
      ").await?;
    Ok(())
  }
  
  pub(crate) async fn create_edition_table(pool: deadpool_postgres::Pool<>) -> anyhow::Result<()> {
    let conn = pool.get().await?;
    conn.simple_query(
      r"CREATE TABLE IF NOT EXISTS editions (
          id varchar(80) not null primary key,
          number bigint,
          sequence_number bigint,
          sha256 varchar(64),
          edition bigint
      )").await?;
      conn.simple_query(r"
        CREATE INDEX IF NOT EXISTS index_editions_number ON editions (number);
        CREATE INDEX IF NOT EXISTS index_editions_sha256 ON editions (sha256);
      ").await?;
    Ok(())
  }
  
  pub(crate) async fn create_editions_total_table(pool: deadpool_postgres::Pool<>) -> anyhow::Result<()> {
    let conn = pool.get().await?;
    conn.simple_query(
      r"CREATE TABLE IF NOT EXISTS editions_total (
          sha256 varchar(64) not null primary key,
          total bigint
      )").await?;
    Ok(())
  }

  pub(crate) async fn create_delegate_table(pool: deadpool_postgres::Pool<>) -> anyhow::Result<()> {
    let conn = pool.get().await?;
    conn.simple_query(
      r"CREATE TABLE IF NOT EXISTS delegates (
          delegate_id varchar(80),
          bootleg_id varchar(80) not null primary key,
          bootleg_number bigint,
          bootleg_sequence_number bigint,
          bootleg_edition bigint
      )").await?;
      conn.simple_query(r"
        CREATE INDEX IF NOT EXISTS index_delegates_number ON delegates (bootleg_number);
        CREATE INDEX IF NOT EXISTS index_delegates_delegate_id ON delegates (delegate_id);
      ").await?;
    Ok(())
  }
  
  pub(crate) async fn create_delegates_total_table(pool: deadpool_postgres::Pool<>) -> anyhow::Result<()> {
    let conn = pool.get().await?;
    conn.simple_query(
      r"CREATE TABLE IF NOT EXISTS delegates_total (
          delegate_id varchar(80) not null primary key,
          total bigint
      )").await?;
    Ok(())
  }

  pub(crate) async fn create_reference_table(pool: deadpool_postgres::Pool<>) -> anyhow::Result<()> {
    let conn = pool.get().await?;
    conn.simple_query(
      r"CREATE TABLE IF NOT EXISTS inscription_references (
          reference_id varchar(80),
          recursive_id varchar(80) not null primary key,
          recursive_number bigint,
          recursive_sequence_number bigint,
          recursive_edition bigint
      )").await?;
      conn.simple_query(r"
        CREATE INDEX IF NOT EXISTS index_references_number ON inscription_references (recursive_number);
        CREATE INDEX IF NOT EXISTS index_references_reference_id ON inscription_references (reference_id);
      ").await?;
    Ok(())
  }
  
  pub(crate) async fn create_references_total_table(pool: deadpool_postgres::Pool<>) -> anyhow::Result<()> {
    let conn = pool.get().await?;
    conn.simple_query(
      r"CREATE TABLE IF NOT EXISTS inscription_references_total (
          reference_id varchar(80) not null primary key,
          total bigint
      )").await?;
    Ok(())
  }

  pub(crate) async fn create_inscription_satributes_table(pool: deadpool_postgres::Pool<>) -> anyhow::Result<()> {
    let conn = pool.get().await?;
    conn.simple_query(
      r"CREATE TABLE IF NOT EXISTS inscription_satributes (
          satribute varchar(30) not null,
          sat bigint,
          inscription_id varchar(80) not null,
          inscription_number bigint,
          inscription_sequence_number bigint,
          satribute_edition bigint,
          CONSTRAINT inscription_satribute_key PRIMARY KEY (satribute, inscription_id)
      )").await?;
      conn.simple_query(r"
        CREATE INDEX IF NOT EXISTS index_inscription_satribute_satribute ON inscription_satributes (satribute);
        CREATE INDEX IF NOT EXISTS index_inscription_satribute_sat ON inscription_satributes (sat);
        CREATE INDEX IF NOT EXISTS index_inscription_satribute_number ON inscription_satributes (inscription_number);
        CREATE INDEX IF NOT EXISTS index_inscription_satribute_id ON inscription_satributes (inscription_id);
      ").await?;
    Ok(())
  }
  
  pub(crate) async fn create_inscription_satributes_total_table(pool: deadpool_postgres::Pool<>) -> anyhow::Result<()> {
    let conn = pool.get().await?;
    conn.simple_query(
      r"CREATE TABLE IF NOT EXISTS inscription_satributes_total (
          satribute varchar(80) not null primary key,
          total bigint
      )").await?;
    Ok(())
  }
  
  pub(crate) async fn create_satributes_table(pool: deadpool_postgres::Pool<>) -> anyhow::Result<()> {
    let conn = pool.get().await?;
    conn.simple_query(
      r"CREATE TABLE IF NOT EXISTS satributes (
        sat bigint not null,
        satribute varchar(30) not null,
        CONSTRAINT satribute_key PRIMARY KEY (sat, satribute)
      )").await?;
    conn.simple_query(r"
      CREATE INDEX IF NOT EXISTS index_satributes_sat ON satributes (sat);
      CREATE INDEX IF NOT EXISTS index_satributes_satribute ON satributes (satribute);
    ").await?;
    Ok(())
  }

  pub(crate) async fn create_collections_table(pool: deadpool_postgres::Pool<>) -> anyhow::Result<()> {
    let conn = pool.get().await?;
    conn.simple_query(
      r"CREATE TABLE IF NOT EXISTS collections (
        id varchar(80) not null,
        number bigint,
        collection_symbol varchar(50) not null,
        off_chain_metadata jsonb,
        CONSTRAINT collection_key PRIMARY KEY (id, collection_symbol)
      )").await?;
    conn.simple_query(r"
      CREATE INDEX IF NOT EXISTS index_collections_id ON collections (id);
      CREATE INDEX IF NOT EXISTS index_collections_number ON collections (number);
      CREATE INDEX IF NOT EXISTS index_collections_collection_symbol ON collections (collection_symbol);
      CREATE INDEX IF NOT EXISTS index_collections_metadata ON collections USING GIN (off_chain_metadata);
    ").await?;
    Ok(())
  }

  pub(crate) async fn create_collections_summary_table(pool: deadpool_postgres::Pool<>) -> anyhow::Result<()> {
    let conn = pool.get().await?;
    conn.simple_query(
      r"CREATE TABLE IF NOT EXISTS collection_summary (
        collection_symbol varchar(50) not null primary key,
        total_inscription_fees bigint,
        total_inscription_size bigint,
        first_inscribed_date bigint,
        last_inscribed_date bigint,
        supply bigint,
        range_start bigint,
        range_end bigint,
        total_volume bigint, 
        total_fees bigint, 
        total_on_chain_footprint bigint
      )").await?;
    Ok(())
  }

  pub(crate) async fn create_collection_list_table(pool: deadpool_postgres::Pool<>) -> anyhow::Result<()> {
    let conn = pool.get().await?;
    conn.simple_query(
      r"CREATE TABLE IF NOT EXISTS collection_list (
        collection_symbol varchar(50) not null primary key,
        name text,
        image_uri text,
        inscription_icon varchar(80),
        description text,
        supply bigint,
        twitter text,
        discord text,
        website text,
        min_inscription_number bigint,
        max_inscription_number bigint,
        date_created bigint
      )").await?;
    conn.simple_query(r"
      CREATE INDEX IF NOT EXISTS index_collection_list_name ON collection_list USING GIN (to_tsvector('english', left(name, 1048575)));
      CREATE INDEX IF NOT EXISTS index_collection_list_description ON collection_list USING GIN (to_tsvector('english', left(description, 1048575)));
      CREATE INDEX IF NOT EXISTS index_min_inscription_number ON collection_list (min_inscription_number);
      CREATE INDEX IF NOT EXISTS index_date_created ON collection_list (date_created);
    ").await?;
    Ok(())
  }

  async fn bulk_insert_metadata(tx: &deadpool_postgres::Transaction<'_>, data: Vec<Metadata>) -> anyhow::Result<()> {
    //tx.simple_query("CREATE TEMP TABLE inserts_ordinals ON COMMIT DROP AS TABLE ordinals WITH NO DATA").await?;
    let copy_stm = r#"COPY ordinals (
      sequence_number, 
      id, 
      content_length, 
      content_type, 
      content_encoding,
      content_category,
      genesis_fee, 
      genesis_height, 
      genesis_transaction, 
      pointer, 
      number, 
      parents, 
      delegate, 
      metaprotocol, 
      on_chain_metadata, 
      sat,
      sat_block,
      satributes,
      charms, 
      timestamp, 
      sha256, 
      text,
      referenced_ids,
      is_json, 
      is_maybe_json, 
      is_bitmap_style, 
      is_recursive) FROM STDIN BINARY"#;
    let col_types = vec![
      Type::INT8,
      Type::VARCHAR,
      Type::INT8,
      Type::TEXT,
      Type::TEXT,
      Type::VARCHAR,
      Type::INT8,
      Type::INT8,
      Type::VARCHAR,
      Type::INT8,
      Type::INT8,
      Type::VARCHAR_ARRAY,
      Type::VARCHAR,
      Type::TEXT,
      Type::JSONB,
      Type::INT8,
      Type::INT8,
      Type::VARCHAR_ARRAY,
      Type::VARCHAR_ARRAY,
      Type::INT8,
      Type::VARCHAR,
      Type::TEXT,
      Type::VARCHAR_ARRAY,
      Type::BOOL,
      Type::BOOL,
      Type::BOOL,
      Type::BOOL
    ];
    let sink = tx.copy_in(copy_stm).await?;
    let writer = BinaryCopyInWriter::new(sink, &col_types);
    pin_mut!(writer);
    for m in data {
      let mut row: Vec<&'_ (dyn ToSql + Sync)> = Vec::new();
      row.push(&m.sequence_number);
      row.push(&m.id);
      row.push(&m.content_length);
      let clean_type = &m.content_type.map(|s| s.replace("\0", ""));
      row.push(clean_type);
      let clean_encoding = &m.content_encoding.map(|s| s.replace("\0", ""));
      row.push(clean_encoding);
      row.push(&m.content_category);
      row.push(&m.genesis_fee);
      row.push(&m.genesis_height);
      row.push(&m.genesis_transaction);
      row.push(&m.pointer);
      row.push(&m.number);
      row.push(&m.parents);
      row.push(&m.delegate);
      let clean_metaprotocol = &m.metaprotocol.map(|s| s.replace("\0", ""));
      row.push(clean_metaprotocol);
      //let clean_metadata = &m.on_chain_metadata.map(|s| s.replace("\0", ""));
      row.push(&m.on_chain_metadata);
      row.push(&m.sat);
      row.push(&m.sat_block);
      row.push(&m.satributes);
      row.push(&m.charms);
      row.push(&m.timestamp);
      row.push(&m.sha256);
      let clean_text = &m.text.map(|s| s.replace("\0", ""));
      row.push(clean_text);
      row.push(&m.referenced_ids);
      row.push(&m.is_json);
      row.push(&m.is_maybe_json);
      row.push(&m.is_bitmap_style);
      row.push(&m.is_recursive);
      writer.as_mut().write(&row).await?;
    }
  
    let _x = writer.finish().await?;
    //println!("Finished writing metadata: {:?}", x);
    //tx.simple_query("INSERT INTO ordinals SELECT * FROM inserts_ordinals ON CONFLICT DO NOTHING").await?;
    Ok(())
  }

  async fn bulk_insert_sat_metadata(tx: &deadpool_postgres::Transaction<'_>, data: Vec<SatMetadata>) -> anyhow::Result<()> {
    tx.simple_query("CREATE TEMP TABLE inserts_sat ON COMMIT DROP AS TABLE sat WITH NO DATA").await?;
    let copy_stm = r#"COPY inserts_sat (
      sat,
      satributes,
      sat_decimal,
      degree,
      name,
      block,
      cycle,
      epoch,
      period,
      third,
      rarity,
      percentile,
      timestamp) FROM STDIN BINARY"#;
    let col_types = vec![
      Type::INT8,
      Type::VARCHAR_ARRAY,
      Type::TEXT,
      Type::TEXT,
      Type::TEXT,
      Type::INT8,
      Type::INT8,
      Type::INT8,
      Type::INT8,
      Type::INT8,
      Type::TEXT,
      Type::TEXT,
      Type::INT8
    ];
    let sink = tx.copy_in(copy_stm).await?;
    let writer = BinaryCopyInWriter::new(sink, &col_types);
    pin_mut!(writer);
    for m in data {
      let mut row: Vec<&'_ (dyn ToSql + Sync)> = Vec::new();
      row.push(&m.sat);
      row.push(&m.satributes);
      row.push(&m.decimal);
      row.push(&m.degree);
      row.push(&m.name);
      row.push(&m.block);
      row.push(&m.cycle);
      row.push(&m.epoch);
      row.push(&m.period);
      row.push(&m.third);
      row.push(&m.rarity);
      row.push(&m.percentile);
      row.push(&m.timestamp);
      writer.as_mut().write(&row).await?;
    }  
    writer.finish().await?;
    tx.simple_query("INSERT INTO sat SELECT * FROM inserts_sat ON CONFLICT DO NOTHING").await?;
    Ok(())
  }

  async fn bulk_insert_content(tx: &deadpool_postgres::Transaction<'_>, data: Vec<(i64, ContentBlob)>) -> anyhow::Result<()> {
    tx.simple_query("CREATE TEMP TABLE inserts_content ON COMMIT DROP AS TABLE content WITH NO DATA").await?;
    let copy_stm = r#"COPY inserts_content (
      content_id,
      sha256, 
      content, 
      content_type,
      content_encoding
    ) FROM STDIN BINARY"#;
    let col_types = vec![
      Type::INT8,
      Type::VARCHAR,
      Type::BYTEA,
      Type::TEXT,
      Type::TEXT
    ];
    let sink = tx.copy_in(copy_stm).await?;
    let writer = BinaryCopyInWriter::new(sink, &col_types);
    pin_mut!(writer);
    for (sequence_number, content) in data {
      let mut row: Vec<&'_ (dyn ToSql + Sync)> = Vec::new();
      row.push(&sequence_number);
      row.push(&content.sha256);
      row.push(&content.content);
      let clean_type = &content.content_type.replace("\0", "");
      row.push(clean_type);
      let clean_encoding = &content.content_encoding.map(|s| s.replace("\0", ""));
      row.push(clean_encoding);
      writer.as_mut().write(&row).await?;
    }
    writer.finish().await?;
    tx.simple_query("INSERT INTO content SELECT content_id, sha256, content, content_type, content_encoding FROM inserts_content ON CONFLICT DO NOTHING").await?;
    Ok(())
  }

  pub(crate) async fn bulk_insert_editions(tx: &deadpool_postgres::Transaction<'_>, metadata_vec: Vec<Metadata>) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    tx.simple_query("CREATE TEMP TABLE inserts_editions ON COMMIT DROP AS TABLE editions WITH NO DATA").await?;
    let copy_stm = r#"COPY inserts_editions (      
      id,
      number,
      sequence_number,
      sha256, 
      edition) FROM STDIN BINARY"#;
    let col_types = vec![
      Type::VARCHAR,
      Type::INT8,
      Type::INT8,
      Type::VARCHAR,
      Type::INT8
    ];
    let sink = tx.copy_in(copy_stm).await?;
    let writer = BinaryCopyInWriter::new(sink, &col_types);
    pin_mut!(writer);
    let edition: i64 = 0;
    for m in metadata_vec {
      let mut row: Vec<&'_ (dyn ToSql + Sync)> = Vec::new();
      row.push(&m.id);
      row.push(&m.number);
      row.push(&m.sequence_number);
      row.push(&m.sha256);
      row.push(&edition);
      writer.as_mut().write(&row).await?;
    }
    writer.finish().await?;
    tx.simple_query("INSERT INTO editions SELECT id, number, sequence_number, coalesce(sha256,''), edition FROM inserts_editions ON CONFLICT DO NOTHING").await?;
    Ok(())
  }

  async fn bulk_insert_satributes(tx: &deadpool_postgres::Transaction<'_>, data: Vec<Satribute>) -> anyhow::Result<()> {
    tx.simple_query("CREATE TEMP TABLE inserts_satributes ON COMMIT DROP AS TABLE satributes WITH NO DATA").await?;
    let copy_stm = r#"COPY inserts_satributes (
      sat,
      satribute) FROM STDIN BINARY"#;
    let col_types = vec![
      Type::INT8,
      Type::VARCHAR
    ];
    let sink = tx.copy_in(copy_stm).await?;
    let writer = BinaryCopyInWriter::new(sink, &col_types);
    pin_mut!(writer);
    for m in data {
      let mut row: Vec<&'_ (dyn ToSql + Sync)> = Vec::new();
      row.push(&m.sat);
      row.push(&m.satribute);
      writer.as_mut().write(&row).await?;
    }  
    writer.finish().await?;
    tx.simple_query("INSERT INTO satributes SELECT * FROM inserts_satributes ON CONFLICT DO NOTHING").await?;
    Ok(())
  }

  pub(crate) async fn get_last_number(pool: deadpool_postgres::Pool<>) -> anyhow::Result<i64> {
    let conn = pool.get().await?;
    let row = conn.query_one("SELECT max(sequence_number) from ordinals", &[]).await?;
    let last_number: Option<i64> = row.get(0);
    Ok(last_number.unwrap_or(-1))
  }

  pub(crate) async fn get_needed_sequence_numbers(status_vector: Arc<Mutex<Vec<SequenceNumberStatus>>>) -> Vec<u64> {
    let mut status_vector = status_vector.lock().await;
    let largest_number_in_vec = status_vector.iter().max_by_key(|status| status.sequence_number).unwrap().sequence_number;
    let mut needed_inscription_numbers: Vec<u64> = Vec::new();
    //Find start of needed numbers
    let mut pending_count=0;
    let mut unknown_count=0;
    let mut error_count=0;
    let mut not_found_count=0;
    let mut success_count=0;
    for status in status_vector.iter() {
      if status.status == "UNKNOWN" || status.status == "ERROR" || status.status == "NOT_FOUND" {
        needed_inscription_numbers.push(status.sequence_number);
      }
      if status.status == "PENDING" {
        pending_count = pending_count + 1;
      }
      if status.status == "UNKNOWN" {
        unknown_count = unknown_count + 1;
      }
      if status.status == "ERROR" || status.status == "ERROR_LOCKED"  {
        error_count = error_count + 1;
      }
      if status.status == "NOT_FOUND" || status.status == "NOT_FOUND_LOCKED" {
        not_found_count = not_found_count + 1;
      }
      if status.status == "SUCCESS" {
        success_count = success_count + 1;
      }
    }
    log::info!("Pending: {}, Unknown: {}, Error: {}, Not Found: {}, Success: {}", pending_count, unknown_count, error_count, not_found_count, success_count);
    //Fill in needed numbers
    let mut needed_length = needed_inscription_numbers.len();
    needed_inscription_numbers.sort();
    if needed_length < INDEX_BATCH_SIZE {
      let mut i = 0;
      while needed_length < INDEX_BATCH_SIZE {        
        i = i + 1;
        needed_inscription_numbers.push(largest_number_in_vec + i);
        needed_length = needed_inscription_numbers.len();
      }
    } else {
      needed_inscription_numbers = needed_inscription_numbers[0..INDEX_BATCH_SIZE].to_vec();
    }
    //Mark as pending
    for number in needed_inscription_numbers.clone() {
      match status_vector.iter_mut().find(|status| status.sequence_number == number) {
        Some(status) => {
          status.status = "PENDING".to_string();
        },
        None => {
          let status = SequenceNumberStatus{
            sequence_number: number,
            status: "PENDING".to_string(),
          };
          status_vector.push(status);
        }
      };
    }
    //Remove successfully processed numbers from vector
    status_vector.retain(|status| status.status != "SUCCESS");
    needed_inscription_numbers
  }

  pub(crate) async fn print_index_timings(timings: Arc<Mutex<Vec<IndexerTimings>>>, n_threads: u32) {
    let mut locked_timings = timings.lock().await;
    // sort & remove incomplete entries    
    locked_timings.retain(|e| e.inscription_start + INDEX_BATCH_SIZE as u64 == e.inscription_end);
    locked_timings.sort_by(|a, b| a.inscription_start.cmp(&b.inscription_start));
    if locked_timings.len() < 1 {
      return;
    }
    //First get the relevant entries
    let mut relevant_timings: Vec<IndexerTimings> = Vec::new();
    let mut last = locked_timings.last().unwrap().inscription_start + INDEX_BATCH_SIZE as u64;
    for timing in locked_timings.iter().rev() {
      if timing.inscription_start == last - INDEX_BATCH_SIZE as u64 {
        relevant_timings.push(timing.clone());
        if relevant_timings.len() == n_threads as usize {
          break;
        }
      } else {
        relevant_timings = Vec::new();
        relevant_timings.push(timing.clone());
      }      
      last = timing.inscription_start;
    }
    if relevant_timings.len() < n_threads as usize {
      return;
    }    
    relevant_timings.sort_by(|a, b| a.inscription_start.cmp(&b.inscription_start));    
    let mut queueing_total = Duration::new(0,0);
    let mut acquire_permit_total = Duration::new(0,0);
    let mut get_numbers_total = Duration::new(0,0);
    let mut get_id_total = Duration::new(0,0);
    let mut get_inscription_total = Duration::new(0,0);
    let mut upload_content_total = Duration::new(0,0);
    let mut get_metadata_total = Duration::new(0,0);
    let mut retrieval_total = Duration::new(0,0);
    let mut insertion_total = Duration::new(0,0);
    let mut metadata_insertion_total = Duration::new(0,0);
    let mut sat_insertion_total = Duration::new(0,0);
    let mut edition_insertion_total = Duration::new(0,0);
    let mut content_insertion_total = Duration::new(0,0);
    let mut locking_total = Duration::new(0,0);
    let mut last_start = relevant_timings.first().unwrap().acquire_permit_start;
    for timing in relevant_timings.iter() {
      queueing_total = queueing_total + timing.acquire_permit_start.duration_since(last_start);
      acquire_permit_total = acquire_permit_total + timing.acquire_permit_end.duration_since(timing.acquire_permit_start);
      get_numbers_total = get_numbers_total + timing.get_numbers_end.duration_since(timing.get_numbers_start);
      get_id_total = get_id_total + timing.get_id_end.duration_since(timing.get_id_start);
      get_inscription_total = get_inscription_total + timing.get_inscription_end.duration_since(timing.get_inscription_start);
      upload_content_total = upload_content_total + timing.upload_content_end.duration_since(timing.upload_content_start);
      get_metadata_total = get_metadata_total + timing.get_metadata_end.duration_since(timing.get_metadata_start);
      retrieval_total = retrieval_total + timing.retrieval;
      insertion_total = insertion_total + timing.insertion;
      metadata_insertion_total = metadata_insertion_total + timing.metadata_insertion;
      sat_insertion_total = sat_insertion_total + timing.sat_insertion;
      edition_insertion_total = edition_insertion_total + timing.edition_insertion;
      content_insertion_total = content_insertion_total + timing.content_insertion;
      locking_total = locking_total + timing.locking;
      last_start = timing.acquire_permit_start;
    }
    let count = relevant_timings.last().unwrap().inscription_end - relevant_timings.first().unwrap().inscription_start+1;
    let total_time = relevant_timings.last().unwrap().get_metadata_end.duration_since(relevant_timings.first().unwrap().get_numbers_start);
    log::info!("Inscriptions {}-{}", relevant_timings.first().unwrap().inscription_start, relevant_timings.last().unwrap().inscription_end);
    log::info!("Total time: {:?}, avg per inscription: {:?}", total_time, total_time/count as u32);
    log::info!("Queueing time avg per thread: {:?}", queueing_total/n_threads); //9 because the first one doesn't have a recorded queueing time
    log::info!("Acquiring Permit time avg per thread: {:?}", acquire_permit_total/n_threads); //should be similar to queueing time
    log::info!("Get numbers time avg per thread: {:?}", get_numbers_total/n_threads);
    log::info!("Get id time avg per thread: {:?}", get_id_total/n_threads);
    log::info!("Get inscription time avg per thread: {:?}", get_inscription_total/n_threads);
    log::info!("Upload content time avg per thread: {:?}", upload_content_total/n_threads);
    log::info!("Get metadata time avg per thread: {:?}", get_metadata_total/n_threads);
    log::info!("--Retrieval time avg per thread: {:?}", retrieval_total/n_threads);
    log::info!("--Insertion time avg per thread: {:?}", insertion_total/n_threads);
    log::info!("--Metadata Insertion time avg per thread: {:?}", metadata_insertion_total/n_threads);
    log::info!("--Sat Insertion time avg per thread: {:?}", sat_insertion_total/n_threads);
    log::info!("--Satribute Insertion time avg per thread: {:?}", edition_insertion_total/n_threads);
    log::info!("--Content Insertion time avg per thread: {:?}", content_insertion_total/n_threads);
    log::info!("--Locking time avg per thread: {:?}", locking_total/n_threads);

    //Remove printed timings
    let to_remove = BTreeSet::from_iter(relevant_timings);
    locked_timings.retain(|e| !to_remove.contains(e));

  }

  //Address Indexer Helper functions
  pub(crate) async fn create_transfers_table(pool: deadpool_postgres::Pool<>) -> anyhow::Result<()> {
    let conn = pool.get().await?;
    conn.simple_query(
      r"CREATE TABLE IF NOT EXISTS transfers (
        id varchar(80) not null,
        block_number bigint not null,
        block_timestamp bigint,
        satpoint varchar(100) not null,
        tx_offset bigint,
        transaction text,
        vout int,
        satpoint_offset bigint,
        address varchar(100),
        previous_address varchar(100),
        price bigint,
        tx_fee bigint,
        tx_size bigint,
        is_genesis boolean,
        PRIMARY KEY (id, block_number, satpoint)
      )").await?;
    conn.simple_query(r"
      CREATE INDEX IF NOT EXISTS index_transfers_id ON transfers (id);
      CREATE INDEX IF NOT EXISTS index_transfers_block ON transfers (block_number);
    ").await?;
    Ok(())
  }
  
  pub(crate) async fn bulk_insert_transfers(tx: &deadpool_postgres::Transaction<'_>, transfer_vec: Vec<Transfer>) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let copy_stm = r#"COPY transfers (
      id,
      block_number,
      block_timestamp,
      satpoint,
      tx_offset,
      transaction,
      vout,
      satpoint_offset,
      address,
      previous_address,
      price,
      tx_fee,
      tx_size,
      is_genesis) FROM STDIN BINARY"#;
    let col_types = vec![
      Type::VARCHAR,
      Type::INT8,
      Type::INT8,
      Type::TEXT,
      Type::INT8,
      Type::TEXT,
      Type::INT4,
      Type::INT8,
      Type::VARCHAR,
      Type::VARCHAR,
      Type::INT8,
      Type::INT8,
      Type::INT8,
      Type::BOOL
    ];
    let sink = tx.copy_in(copy_stm).await?;
    let writer = BinaryCopyInWriter::new(sink, &col_types);
    pin_mut!(writer);
    for m in transfer_vec {
      let mut row: Vec<&'_ (dyn ToSql + Sync)> = Vec::new();
      row.push(&m.id);
      row.push(&m.block_number);
      row.push(&m.block_timestamp);
      row.push(&m.satpoint);
      row.push(&m.tx_offset);
      row.push(&m.transaction);
      row.push(&m.vout);
      row.push(&m.offset);
      row.push(&m.address);
      row.push(&m.previous_address);
      row.push(&m.price);
      row.push(&m.tx_fee);
      row.push(&m.tx_size);
      row.push(&m.is_genesis);
      writer.as_mut().write(&row).await?;
    }
    writer.finish().await?;
    Ok(())
  }

  pub(crate) async fn create_address_table(pool: deadpool_postgres::Pool<>) -> anyhow::Result<()> {
    let conn = pool.get().await?;
    conn.simple_query(
      r"CREATE TABLE IF NOT EXISTS addresses (
        id varchar(80) not null primary key,
        block_number bigint not null,
        block_timestamp bigint,
        satpoint varchar(100),
        tx_offset bigint,
        transaction text,
        vout int,
        satpoint_offset bigint,
        address varchar(100),
        previous_address varchar(100),
        price bigint,
        tx_fee bigint,
        tx_size bigint,
        is_genesis boolean
      )").await?;
    conn.simple_query(r"
      CREATE INDEX IF NOT EXISTS index_address ON addresses (address);
    ").await?;
    Ok(())
  }
  
  pub(crate) async fn bulk_insert_addresses(tx: &deadpool_postgres::Transaction<'_>, mut transfer_vec: Vec<Transfer>) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    //ON CONFLICT DO UPDATE command cannot affect row a second time, so we reverse & dedup (effectively keeping the last transfer in block)
    transfer_vec.reverse();
    transfer_vec.dedup_by(|a, b| a.id == b.id);
    tx.simple_query("CREATE TEMP TABLE inserts_addresses ON COMMIT DROP AS TABLE addresses WITH NO DATA").await?;
    let copy_stm = r#"COPY inserts_addresses (
      id,
      block_number,
      block_timestamp,
      satpoint,
      tx_offset,
      transaction,
      vout,
      satpoint_offset,
      address,
      previous_address,
      price,
      tx_fee,
      tx_size,
      is_genesis) FROM STDIN BINARY"#;
    let col_types = vec![
      Type::VARCHAR,
      Type::INT8,
      Type::INT8,
      Type::TEXT,
      Type::INT8,
      Type::TEXT,
      Type::INT4,
      Type::INT8,
      Type::VARCHAR,
      Type::VARCHAR,
      Type::INT8,
      Type::INT8,
      Type::INT8,
      Type::BOOL
    ];
    let sink = tx.copy_in(copy_stm).await?;
    let writer = BinaryCopyInWriter::new(sink, &col_types);
    pin_mut!(writer);
    for m in transfer_vec {
      let mut row: Vec<&'_ (dyn ToSql + Sync)> = Vec::new();
      row.push(&m.id);
      row.push(&m.block_number);
      row.push(&m.block_timestamp);
      row.push(&m.satpoint);
      row.push(&m.tx_offset);
      row.push(&m.transaction);
      row.push(&m.vout);
      row.push(&m.offset);
      row.push(&m.address);
      row.push(&m.previous_address);
      row.push(&m.price);
      row.push(&m.tx_fee);
      row.push(&m.tx_size);
      row.push(&m.is_genesis);
      writer.as_mut().write(&row).await?;
    }
    writer.finish().await?;
    tx.simple_query("INSERT INTO addresses SELECT * FROM inserts_addresses ON CONFLICT (id) DO UPDATE SET 
      block_number = EXCLUDED.block_number, 
      block_timestamp = EXCLUDED.block_timestamp,
      satpoint = EXCLUDED.satpoint,
      tx_offset = EXCLUDED.tx_offset,
      transaction = EXCLUDED.transaction,
      vout = EXCLUDED.vout,
      satpoint_offset = EXCLUDED.satpoint_offset,
      address = EXCLUDED.address,
      is_genesis = EXCLUDED.is_genesis").await?;
    Ok(())
  }

  pub(crate) async fn get_start_block(pool: deadpool) -> Result<u32, Box<dyn std::error::Error>> {
    let conn = pool.get().await?;
    let row = conn.query_one("SELECT max(block_number) from blockstats", &[]).await;
    let last_block = match row {
      Ok(row) => {
        let last_block: Option<i64> = row.get(0);
        last_block.unwrap_or(-1)
      },
      Err(_) => -1
    };
    Ok((last_block + 1) as u32)
  }

  pub(crate) async fn bulk_insert_blockstats(tx: &deadpool_postgres::Transaction<'_>, blockstats: Vec<BlockStats>) -> Result<(), Box<dyn std::error::Error>> {
    let copy_stm = r#"COPY blockstats (
      block_number,
      block_timestamp,
      block_tx_count,
      block_size,
      block_fees,
      min_fee,
      max_fee,
      average_fee
    ) FROM STDIN BINARY"#;
    let col_types = vec![
      Type::INT8,
      Type::INT8,
      Type::INT8,
      Type::INT8,
      Type::INT8,
      Type::INT8,
      Type::INT8,
      Type::INT8
    ];
    let sink = tx.copy_in(copy_stm).await?;
    let writer = BinaryCopyInWriter::new(sink, &col_types);
    pin_mut!(writer);
    for m in blockstats {
      let mut row: Vec<&'_ (dyn ToSql + Sync)> = Vec::new();
      row.push(&m.block_number);
      row.push(&m.block_timestamp);
      row.push(&m.block_tx_count);
      row.push(&m.block_size);
      row.push(&m.block_fees);
      row.push(&m.min_fee);
      row.push(&m.max_fee);
      row.push(&m.average_fee);
      writer.as_mut().write(&row).await?;
    }
    writer.finish().await?;
    Ok(())
  }

  pub(crate) async fn bulk_insert_inscription_blockstats(tx: &deadpool_postgres::Transaction<'_>, block_number: i64) -> Result<(), Box<dyn std::error::Error>> {
    tx.query(
      r"INSERT INTO inscription_blockstats (block_number, block_inscription_count, block_inscription_size, block_inscription_fees) 
      SELECT $1 as block_number, count(*) as block_inscription_count, coalesce(sum(tx_size),0) as block_inscription_size, coalesce(sum(tx_fee),0) as block_inscription_fees from transfers where block_number = $1 and is_genesis"
    , &[&block_number]).await?;
    tx.query(
      r"INSERT INTO inscription_blockstats (block_number, block_transfer_count, block_transfer_size, block_transfer_fees, block_volume) 
      SELECT $1 as block_number, count(*) as block_transfer_count, coalesce(sum(tx_size),0) as block_transfer_size, coalesce(sum(tx_fee),0) as block_transfer_fees, coalesce(sum(price),0) as block_volume from transfers where block_number = $1 and NOT is_genesis
      ON CONFLICT (block_number) DO UPDATE SET
      block_transfer_count = EXCLUDED.block_transfer_count,
      block_transfer_size = EXCLUDED.block_transfer_size,
      block_transfer_fees = EXCLUDED.block_transfer_fees,
      block_volume = EXCLUDED.block_volume"
    , &[&block_number]).await?;
    Ok(())
  }

  pub(crate) async fn create_blockstats_table(pool: deadpool_postgres::Pool<>) -> anyhow::Result<()> {
    let conn = pool.get().await?;
    conn.simple_query(
      r"CREATE TABLE IF NOT EXISTS blockstats (
        block_number bigint not null primary key,
        block_timestamp bigint not null,
        block_tx_count bigint,
        block_size bigint,
        block_fees bigint,
        min_fee bigint,
        max_fee bigint,
        average_fee bigint
      )").await?;
    Ok(())
  }

  pub(crate) async fn create_inscription_blockstats_table(pool: deadpool_postgres::Pool<>) -> anyhow::Result<()> {
    let conn = pool.get().await?;
    conn.simple_query(
      r"CREATE TABLE IF NOT EXISTS inscription_blockstats (
        block_number bigint not null primary key,
        block_inscription_count bigint,
        block_inscription_size bigint,
        block_inscription_fees bigint,
        block_transfer_count bigint,
        block_transfer_size bigint,
        block_transfer_fees bigint,
        block_volume bigint
      )").await?;
    Ok(())
  }
  
  //Server api functions
  async fn root() -> &'static str {
"If Bitcoin is to change the culture of money, it needs to be cool. Ordinals was the missing piece. The path to $1m is preordained"
  }

  fn parse_and_validate_inscription_params(params: InscriptionQueryParams) -> anyhow::Result<ParsedInscriptionQueryParams> {
    //1. parse params
    let params = ParsedInscriptionQueryParams::from(params);
    //2. validate params
    for content_type in &params.content_types {
      if !["text", "image", "gif", "audio", "video", "html", "json", "namespace"].contains(&content_type.as_str()) {
        return Err(anyhow!("Invalid content_type: {}", content_type));
      }
    }
    for satribute in &params.satributes {
      if !["vintage", "nakamoto", "firsttransaction", "palindrome", "pizza", "block9", "block9_450", "block78", "alpha", "omega", "uniform_palinception", "perfect_palinception", "block286", "jpeg", 
           "uncommon", "rare", "epic", "legendary", "mythic", "black_uncommon", "black_rare", "black_epic", "black_legendary"].contains(&satribute.as_str()) {
        return Err(anyhow!("Invalid satribute: {}", satribute));
      }
    }
    for charm in &params.charms {
      if !["coin", "cursed", "epic", "legendary", "lost", "nineball", "rare", "reinscription", "unbound", "uncommon", "vindicated"].contains(&charm.as_str()) {
        return Err(anyhow!("Invalid charm: {}", charm));
      }
    }
    if !["newest", "oldest", "newest_sat", "oldest_sat", "rarest_sat", "commonest_sat", "biggest", "smallest", "highest_fee", "lowest_fee"].contains(&params.sort_by.as_str()) {
      return Err(anyhow!("Invalid sort_by: {}", params.sort_by));
    }
    Ok(params)
  }

  async fn home(State(server_config): State<ApiServerConfig>) -> impl axum::response::IntoResponse {
    let content_blob = match Self::get_ordinal_content(server_config.deadpool,  "6fb976ab49dcec017f1e201e84395983204ae1a7c2abf7ced0a85d692e442799i0".to_string()).await {
      Ok(content_blob) => content_blob,
      Err(error) => {
        log::warn!("Error getting /home: {}", error);
        return (
          StatusCode::INTERNAL_SERVER_ERROR,
          format!("Error retrieving 6fb976ab49dcec017f1e201e84395983204ae1a7c2abf7ced0a85d692e442799i0"),
        ).into_response();
      }
    };
    let bytes = content_blob.content;
    let content_type = content_blob.content_type;
    (
        ([(axum::http::header::CONTENT_TYPE, content_type)]),
        bytes,
    ).into_response()
  }

  async fn set_header<B>(response: Response<B>) -> Response<B> {
    //response.headers_mut().insert("cache-control", "public, max-age=31536000, immutable".parse().unwrap());
    response
  }

  async fn inscription(Path(inscription_id): Path<InscriptionId>, State(server_config): State<ApiServerConfig>) -> impl axum::response::IntoResponse {
    let content_blob = match Self::get_ordinal_content(server_config.deadpool, inscription_id.to_string()).await {
      Ok(content_blob) => content_blob,
      Err(error) => {
        log::warn!("Error getting /inscription: {}", error);
        if error.to_string().contains("unexpected number of rows"){
          return (
            StatusCode::NOT_FOUND,
            format!("Inscription not found {}", inscription_id.to_string()),
          ).into_response();
        } else {
          return (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Error retrieving {}", inscription_id.to_string()),
          ).into_response();
        }
      }
    };
    let bytes = content_blob.content;
    let content_type = content_blob.content_type;
    let content_encoding = content_blob.content_encoding;
    let cache_control = if content_blob.sha256 == "NOT_INDEXED" {
      "no-store, no-cache, must-revalidate, max-age=0"
    } else {
      "public, max-age=31536000"
    };
    let mut header_map = HeaderMap::new();
    header_map.insert("content-type", content_type.parse().unwrap());
    header_map.insert("cache-control", cache_control.parse().unwrap());
    if let Some(encoding) = content_encoding {
      header_map.insert("content-encoding", encoding.parse().unwrap());
    }

    (header_map, bytes).into_response()
  }

  async fn inscription_number(Path(number): Path<i64>, State(server_config): State<ApiServerConfig>) -> impl axum::response::IntoResponse {
    let content_blob = match Self::get_ordinal_content_by_number(server_config.deadpool,  number).await {
      Ok(content_blob) => content_blob,
      Err(error) => {
        log::warn!("Error getting /inscription_number: {}", error);
        return (
          StatusCode::INTERNAL_SERVER_ERROR,
          format!("Error retrieving {}", number.to_string()),
        ).into_response();
      }
    };
    let bytes = content_blob.content;
    let content_type = content_blob.content_type;
    let content_encoding = content_blob.content_encoding;
    let cache_control = if content_blob.sha256 == "NOT_INDEXED" {
      "no-store, no-cache, must-revalidate, max-age=0"
    } else {
      "public, max-age=31536000"
    };
    let mut header_map = HeaderMap::new();
    header_map.insert("content-type", content_type.parse().unwrap());
    header_map.insert("cache-control", cache_control.parse().unwrap());
    if let Some(encoding) = content_encoding {
      header_map.insert("content-encoding", encoding.parse().unwrap());
    }

    (header_map, bytes).into_response()
  }

  async fn inscription_sha256(Path(sha256): Path<String>, State(server_config): State<ApiServerConfig>) -> impl axum::response::IntoResponse {
    let content_blob = match Self::get_ordinal_content_by_sha256(server_config.deadpool, sha256.clone(), None, None).await {
      Ok(content_blob) => content_blob,
      Err(error) => {
        log::warn!("Error getting /inscription_sha256: {}", error);
        return (
          StatusCode::INTERNAL_SERVER_ERROR,
          format!("Error retrieving inscription by sha256: {}", sha256),
        ).into_response();
      }
    };
    let bytes = content_blob.content;
    let content_type = content_blob.content_type;
    let content_encoding = content_blob.content_encoding;
    let cache_control = if content_blob.sha256 == "NOT_INDEXED" {
      "no-store, no-cache, must-revalidate, max-age=0"
    } else {
      "public, max-age=31536000"
    };
    let mut header_map = HeaderMap::new();
    header_map.insert("content-type", content_type.parse().unwrap());
    header_map.insert("cache-control", cache_control.parse().unwrap());
    if let Some(encoding) = content_encoding {
      header_map.insert("content-encoding", encoding.parse().unwrap());
    }

    (header_map, bytes).into_response()
  }

  async fn inscription_metadata(Path(inscription_id): Path<InscriptionId>, State(server_config): State<ApiServerConfig>) -> impl axum::response::IntoResponse {
    let metadata = match Self::get_ordinal_metadata(server_config.deadpool, inscription_id.to_string()).await {
      Ok(metadata) => metadata,
      Err(error) => {
        log::warn!("Error getting /inscription_metadata: {}", error);
        return (
          StatusCode::INTERNAL_SERVER_ERROR,
          format!("Error retrieving metadata for {}", inscription_id.to_string()),
        ).into_response();
      }
    
    };
    (
      ([(axum::http::header::CONTENT_TYPE, "application/json"),
        (axum::http::header::CACHE_CONTROL, "public, max-age=31536000")]),
      Json(metadata),
    ).into_response()
  }

  async fn inscription_metadata_number(Path(number): Path<i64>, State(server_config): State<ApiServerConfig>) -> impl axum::response::IntoResponse {
    let metadata = match Self::get_ordinal_metadata_by_number(server_config.deadpool, number).await {
      Ok(metadata) => metadata,
      Err(error) => {
        log::warn!("Error getting /inscription_metadata_number: {}", error);
        return (
          StatusCode::INTERNAL_SERVER_ERROR,
          format!("Error retrieving metadata for {}", number.to_string()),
        ).into_response();
      }
    };
    (
      ([(axum::http::header::CONTENT_TYPE, "application/json"),
        (axum::http::header::CACHE_CONTROL, "public, max-age=31536000")]),
      Json(metadata),
    ).into_response()
  }

  async fn inscription_edition(Path(inscription_id): Path<InscriptionId>, State(server_config): State<ApiServerConfig>) -> impl axum::response::IntoResponse {
    let edition = match Self::get_inscription_edition(server_config.deadpool, inscription_id.to_string()).await {
      Ok(edition) => edition,
      Err(error) => {
        log::warn!("Error getting /inscription_edition: {}", error);
        return (
          StatusCode::INTERNAL_SERVER_ERROR,
          format!("Error retrieving edition for {}", inscription_id.to_string()),
        ).into_response();
      }
    };
    (
      ([(axum::http::header::CONTENT_TYPE, "application/json")]),
      Json(edition),
    ).into_response()
  }

  async fn inscription_edition_number(Path(number): Path<i64>, State(server_config): State<ApiServerConfig>) -> impl axum::response::IntoResponse {
    let edition = match Self::get_inscription_edition_number(server_config.deadpool, number).await {
      Ok(edition) => edition,
      Err(error) => {
        log::warn!("Error getting /inscription_edition_number: {}", error);
        return (
          StatusCode::INTERNAL_SERVER_ERROR,
          format!("Error retrieving edition for {}", number),
        ).into_response();
      }
    
    };
    (
      ([(axum::http::header::CONTENT_TYPE, "application/json")]),
      Json(edition),
    ).into_response()
  }

  async fn inscription_editions_sha256(Path(sha256): Path<String>, params: Query<PaginationParams>, State(server_config): State<ApiServerConfig>) -> impl axum::response::IntoResponse {
    let editions = match Self::get_matching_inscriptions_by_sha256(server_config.deadpool, sha256.clone(), params.0).await {
      Ok(editions) => editions,
      Err(error) => {
        log::warn!("Error getting /inscription_editions_sha256: {}", error);
        return (
          StatusCode::INTERNAL_SERVER_ERROR,
          format!("Error retrieving editions for {}", sha256),
        ).into_response();
      }
    };
    (
      ([(axum::http::header::CONTENT_TYPE, "application/json")]),
      Json(editions),
    ).into_response()
  }

  async fn inscription_children(Path(inscription_id): Path<InscriptionId>, params: Query<PaginationParams>, State(server_config): State<ApiServerConfig>) -> impl axum::response::IntoResponse {
    let editions = match Self::get_inscription_children(server_config.deadpool, inscription_id.to_string(), params.0).await {
      Ok(editions) => editions,
      Err(error) => {
        log::warn!("Error getting /inscription_children: {}", error);
        return (
          StatusCode::INTERNAL_SERVER_ERROR,
          format!("Error retrieving children for {}", inscription_id.to_string()),
        ).into_response();
      }
    };
    (
      ([(axum::http::header::CONTENT_TYPE, "application/json")]),
      Json(editions),
    ).into_response()
  }

  async fn inscription_children_number(Path(number): Path<i64>, params: Query<PaginationParams>, State(server_config): State<ApiServerConfig>) -> impl axum::response::IntoResponse {
    let editions = match Self::get_inscription_children_by_number(server_config.deadpool, number, params.0).await {
      Ok(editions) => editions,
      Err(error) => {
        log::warn!("Error getting /inscription_children_number: {}", error);
        return (
          StatusCode::INTERNAL_SERVER_ERROR,
          format!("Error retrieving children for {}", number),
        ).into_response();
      }
    
    };
    (
      ([(axum::http::header::CONTENT_TYPE, "application/json")]),
      Json(editions),
    ).into_response()
  }

  async fn inscription_referenced_by(Path(inscription_id): Path<InscriptionId>, params: Query<PaginationParams>, State(server_config): State<ApiServerConfig>) -> impl axum::response::IntoResponse {
    let referenced_by = match Self::get_inscription_referenced_by(server_config.deadpool, inscription_id.to_string(), params.0).await {
      Ok(referenced_by) => referenced_by,
      Err(error) => {
        log::warn!("Error getting /inscription_referenced_by: {}", error);
        return (
          StatusCode::INTERNAL_SERVER_ERROR,
          format!("Error retrieving referenced by for {}", inscription_id.to_string()),
        ).into_response();
      }
    };
    (
      ([(axum::http::header::CONTENT_TYPE, "application/json")]),
      Json(referenced_by),
    ).into_response()
  }

  async fn inscription_referenced_by_number(Path(number): Path<i64>, params: Query<PaginationParams>, State(server_config): State<ApiServerConfig>) -> impl axum::response::IntoResponse {
    let referenced_by = match Self::get_inscription_referenced_by_number(server_config.deadpool, number, params.0).await {
      Ok(referenced_by) => referenced_by,
      Err(error) => {
        log::warn!("Error getting /inscription_referenced_by_number: {}", error);
        return (
          StatusCode::INTERNAL_SERVER_ERROR,
          format!("Error retrieving referenced by for {}", number),
        ).into_response();
      }
    
    };
    (
      ([(axum::http::header::CONTENT_TYPE, "application/json")]),
      Json(referenced_by),
    ).into_response()
  }

  async fn inscriptions_in_block(Path(block): Path<i64>, params: Query<InscriptionQueryParams>, State(server_config): State<ApiServerConfig>) -> impl axum::response::IntoResponse {
    let parsed_params = match Self::parse_and_validate_inscription_params(params.0) {
      Ok(parsed_params) => parsed_params,
      Err(error) => {
        log::warn!("Error getting /inscriptions_in_block: {}", error);
        return (
          StatusCode::BAD_REQUEST,
          format!("Error parsing and validating params: {}", error),
        ).into_response();
      }
    };
    let inscriptions = match Self::get_inscriptions_within_block(server_config.deadpool, block, parsed_params).await {
      Ok(inscriptions) => inscriptions,
      Err(error) => {
        log::warn!("Error getting /inscriptions_in_block: {}", error);
        return (
          StatusCode::INTERNAL_SERVER_ERROR,
          format!("Error retrieving inscriptions for block {}", block.to_string()),
        ).into_response();
      }
    };
    (
      ([(axum::http::header::CONTENT_TYPE, "application/json"),
      (axum::http::header::CACHE_CONTROL, "public, max-age=31536000")]),
      Json(inscriptions),
    ).into_response()
  }

  async fn random_inscription(State(server_config): State<ApiServerConfig>) -> impl axum::response::IntoResponse {
    let mut rng = rand::rngs::StdRng::from_entropy();
    let random_float = rng.gen::<f64>();
    let (inscription_number, _band) = match Self::get_random_inscription(server_config.deadpool, random_float).await {
      Ok((inscription_number, band)) => (inscription_number, band),
      Err(error) => {
        log::warn!("Error getting /random_inscription: {}", error);
        return (
          StatusCode::INTERNAL_SERVER_ERROR,
          format!("Error retrieving random inscription"),
        ).into_response();
      }
    };
    (
      ([(axum::http::header::CONTENT_TYPE, "application/json")]),
      Json(inscription_number),
    ).into_response()
  }

  async fn random_inscriptions(n: Query<QueryNumber>, State(server_config): State<ApiServerConfig>, session: Session<SessionNullPool>) -> impl axum::response::IntoResponse {
    let bands: Vec<(f64, f64)> = session.get("bands_seen").unwrap_or(Vec::new());
    for band in bands.iter() {
        println!("Band: {:?}", band);
    }
    let n = n.0.n;
    let (inscription_numbers, new_bands) = match Self::get_random_inscriptions(server_config.deadpool, n, bands).await {
      Ok((inscription_numbers, new_bands)) => (inscription_numbers, new_bands),
      Err(error) => {
        log::warn!("Error getting /random_inscriptions: {}", error);
        return (
          StatusCode::INTERNAL_SERVER_ERROR,
          format!("Error retrieving random inscriptions"),
        ).into_response();
      }
    };
    session.set("bands_seen", new_bands);
    (
      ([(axum::http::header::CONTENT_TYPE, "application/json")]),
      Json(inscription_numbers),
    ).into_response()
  }

  async fn recent_inscriptions(n: Query<QueryNumber>, State(server_config): State<ApiServerConfig>) -> impl axum::response::IntoResponse {
    let n = n.0.n;
    let inscriptions = match Self::get_recent_inscriptions(server_config.deadpool, n).await {
      Ok(inscriptions) => inscriptions,
      Err(error) => {
        log::warn!("Error getting /recent_inscriptions: {}", error);
        return (
          StatusCode::INTERNAL_SERVER_ERROR,
          format!("Error retrieving recent inscriptions"),
        ).into_response();
      }
    };
    (
      ([(axum::http::header::CONTENT_TYPE, "application/json")]),
      Json(inscriptions),
    ).into_response()
  }

  async fn inscriptions(params: Query<InscriptionQueryParams>, State(server_config): State<ApiServerConfig>) -> impl axum::response::IntoResponse {
    //1. parse params
    let params = ParsedInscriptionQueryParams::from(params.0);
    //2. validate params
    for content_type in &params.content_types {
      if !["text", "image", "gif", "audio", "video", "html", "json", "namespace"].contains(&content_type.as_str()) {
        return (
          StatusCode::BAD_REQUEST,
          format!("Invalid content_type: {}", content_type),
        ).into_response();
      }
    }
    for satribute in &params.satributes {
      if !["vintage", "nakamoto", "firsttransaction", "palindrome", "pizza", "block9", "block9_450", "block78", "alpha", "omega", "uniform_palinception", "perfect_palinception", "block286", "jpeg", 
           "uncommon", "rare", "epic", "legendary", "mythic", "black_uncommon", "black_rare", "black_epic", "black_legendary"].contains(&satribute.as_str()) {
        return (
          StatusCode::BAD_REQUEST,
          format!("Invalid satribute: {}", satribute),
        ).into_response();
      }
    }
    for charm in &params.charms {
      if !["coin", "cursed", "epic", "legendary", "lost", "nineball", "rare", "reinscription", "unbound", "uncommon", "vindicated"].contains(&charm.as_str()) {
        return (
          StatusCode::BAD_REQUEST,
          format!("Invalid charm: {}", charm),
        ).into_response();
      }
    }
    if !["newest", "oldest", "newest_sat", "oldest_sat", "rarest_sat", "commonest_sat", "biggest", "smallest", "highest_fee", "lowest_fee"].contains(&params.sort_by.as_str()) {
      return (
        StatusCode::BAD_REQUEST,
        format!("Invalid sort_by: {}", params.sort_by),
      ).into_response();
    }
    let inscriptions = match Self::get_inscriptions(server_config.deadpool, params).await {
      Ok(inscriptions) => inscriptions,
      Err(error) => {
        log::warn!("Error getting /inscriptions: {}", error);
        return (
          StatusCode::INTERNAL_SERVER_ERROR,
          format!("Error retrieving inscriptions"),
        ).into_response();
      }
    };
    (
      ([(axum::http::header::CONTENT_TYPE, "application/json")]),
      Json(inscriptions),
    ).into_response()
  }

  async fn inscription_last_transfer(Path(inscription_id): Path<InscriptionId>, State(server_config): State<ApiServerConfig>) -> impl axum::response::IntoResponse {
    let transfer = match Self::get_last_ordinal_transfer(server_config.deadpool, inscription_id.to_string()).await {
      Ok(transfer) => transfer,
      Err(error) => {
        log::warn!("Error getting /inscription_last_transfer: {}", error);
        return (
          StatusCode::INTERNAL_SERVER_ERROR,
          format!("Error retrieving last transfer for {}", inscription_id.to_string()),
        ).into_response();
      }    
    };
    (
      ([(axum::http::header::CONTENT_TYPE, "application/json")]),
      Json(transfer),
    ).into_response()
  }

  async fn inscription_last_transfer_number(Path(number): Path<i64>, State(server_config): State<ApiServerConfig>) -> impl axum::response::IntoResponse {
    let transfer = match Self::get_last_ordinal_transfer_by_number(server_config.deadpool, number).await {
      Ok(transfer) => transfer,
      Err(error) => {
        log::warn!("Error getting /inscription_last_transfer_number: {}", error);
        return (
          StatusCode::INTERNAL_SERVER_ERROR,
          format!("Error retrieving last transfer for {}", number),
        ).into_response();
      }
    };
    (
      ([(axum::http::header::CONTENT_TYPE, "application/json")]),
      Json(transfer),
    ).into_response()
  }

  async fn inscription_transfers(Path(inscription_id): Path<InscriptionId>, State(server_config): State<ApiServerConfig>) -> impl axum::response::IntoResponse {
    let transfers = match Self::get_ordinal_transfers(server_config.deadpool, inscription_id.to_string()).await {
      Ok(transfers) => transfers,
      Err(error) => {
        log::warn!("Error getting /inscription_transfers: {}", error);
        return (
          StatusCode::INTERNAL_SERVER_ERROR,
          format!("Error retrieving transfers for {}", inscription_id.to_string()),
        ).into_response();
      }
    };
    (
      ([(axum::http::header::CONTENT_TYPE, "application/json")]),
      Json(transfers),
    ).into_response()
  }

  async fn inscription_transfers_number(Path(number): Path<i64>, State(server_config): State<ApiServerConfig>) -> impl axum::response::IntoResponse {
    let transfers = match Self::get_ordinal_transfers_by_number(server_config.deadpool, number).await {
      Ok(transfers) => transfers,
      Err(error) => {
        log::warn!("Error getting /inscription_transfers_number: {}", error);
        return (
          StatusCode::INTERNAL_SERVER_ERROR,
          format!("Error retrieving transfers for {}", number),
        ).into_response();
      }
    };
    (
      ([(axum::http::header::CONTENT_TYPE, "application/json")]),
      Json(transfers),
    ).into_response()
  }

  async fn inscriptions_in_address(Path(address): Path<String>, params: Query<InscriptionQueryParams>, State(server_config): State<ApiServerConfig>) -> impl axum::response::IntoResponse {
    let parsed_params = match Self::parse_and_validate_inscription_params(params.0) {
      Ok(parsed_params) => parsed_params,
      Err(error) => {
        log::warn!("Error getting /inscriptions_in_collection: {}", error);
        return (
          StatusCode::BAD_REQUEST,
          format!("Error parsing and validating params: {}", error),
        ).into_response();
      }
    };
    let inscriptions: Vec<TransferWithMetadata> = match Self::get_inscriptions_by_address(server_config.deadpool, address.clone(), parsed_params).await {
      Ok(inscriptions) => inscriptions,
      Err(error) => {
        log::warn!("Error getting /inscriptions_in_address: {}", error);
        return (
          StatusCode::INTERNAL_SERVER_ERROR,
          format!("Error retrieving inscriptions for {}", address),
        ).into_response();
      }
    };
    (
      ([(axum::http::header::CONTENT_TYPE, "application/json")]),
      Json(inscriptions),
    ).into_response()
  }

  async fn inscriptions_on_sat(Path(sat): Path<i64>, State(server_config): State<ApiServerConfig>) -> impl axum::response::IntoResponse {
    let inscriptions: Vec<FullMetadata> = match Self::get_inscriptions_on_sat(server_config.deadpool, sat).await {
      Ok(inscriptions) => inscriptions,
      Err(error) => {
        log::warn!("Error getting /inscriptions_on_sat: {}", error);
        return (
          StatusCode::INTERNAL_SERVER_ERROR,
          format!("Error retrieving inscriptions for {}", sat),
        ).into_response();
      }
    };
    (
      ([(axum::http::header::CONTENT_TYPE, "application/json")]),
      Json(inscriptions),
    ).into_response()
  }

  async fn inscriptions_in_sat_block(Path(block): Path<i64>, params: Query<InscriptionQueryParams>, State(server_config): State<ApiServerConfig>) -> impl axum::response::IntoResponse {
    let parsed_params = match Self::parse_and_validate_inscription_params(params.0) {
      Ok(parsed_params) => parsed_params,
      Err(error) => {
        log::warn!("Error getting /inscriptions_in_collection: {}", error);
        return (
          StatusCode::BAD_REQUEST,
          format!("Error parsing and validating params: {}", error),
        ).into_response();
      }
    };
    let inscriptions = match Self::get_inscriptions_in_sat_block(server_config.deadpool, block, parsed_params).await {
      Ok(inscriptions) => inscriptions,
      Err(error) => {
        log::warn!("Error getting /inscriptions_in_sat_block: {}", error);
        return (
          StatusCode::INTERNAL_SERVER_ERROR,
          format!("Error retrieving inscriptions for {}", block),
        ).into_response();
      }
    };
    (
      ([(axum::http::header::CONTENT_TYPE, "application/json")]),
      Json(inscriptions),
    ).into_response()
  }

  async fn sat_metadata(Path(sat): Path<i64>, State(server_config): State<ApiServerConfig>) -> impl axum::response::IntoResponse {
    let sat_metadata = match Self::get_sat_metadata(server_config.deadpool, sat).await {
      Ok(sat_metadata) => sat_metadata,
      Err(error) => {
        log::warn!("Error getting /sat_metadata: {}", error);
        return (
          StatusCode::INTERNAL_SERVER_ERROR,
          format!("Error retrieving metadata for {}", sat),
        ).into_response();
      }    
    };
    (
      ([(axum::http::header::CONTENT_TYPE, "application/json")]),
      Json(sat_metadata),
    ).into_response()
  }

  async fn satributes(Path(sat): Path<i64>, State(server_config): State<ApiServerConfig>) -> impl axum::response::IntoResponse {
    let satributes = match Self::get_satributes(server_config.deadpool, sat).await {
      Ok(satributes) => satributes,
      Err(error) => {
        log::warn!("Error getting /satributes: {}", error);
        return (
          StatusCode::INTERNAL_SERVER_ERROR,
          format!("Error retrieving satributes for {}", sat),
        ).into_response();
      }
    };
    (
      ([(axum::http::header::CONTENT_TYPE, "application/json")]),
      Json(satributes),
    ).into_response()
  }

  async fn collection_summary(Path(collection_symbol): Path<String>, State(server_config): State<ApiServerConfig>) -> impl axum::response::IntoResponse {
    let collection_summary = match Self::get_collection_summary(server_config.deadpool, collection_symbol.clone()).await {
      Ok(collection_summary) => collection_summary,
      Err(error) => {
        log::warn!("Error getting /collection_summary: {}", error);
        return (
          StatusCode::INTERNAL_SERVER_ERROR,
          format!("Error retrieving collection summary for {}", collection_symbol),
        ).into_response();
      }    
    };
    (
      ([(axum::http::header::CONTENT_TYPE, "application/json")]),
      Json(collection_summary),
    ).into_response()
  }

  async fn collection_holders(Path(collection_symbol): Path<String>, params: Query<PaginationParams>, State(server_config): State<ApiServerConfig>) -> impl axum::response::IntoResponse {
    let collection_holders = match Self::get_collection_holders(server_config.deadpool, collection_symbol.clone(), params.0).await {
      Ok(collection_holders) => collection_holders,
      Err(error) => {
        log::warn!("Error getting /collection_holders: {}", error);
        return (
          StatusCode::INTERNAL_SERVER_ERROR,
          format!("Error retrieving collection_holders summary for {}", collection_symbol),
        ).into_response();
      }    
    };
    (
      ([(axum::http::header::CONTENT_TYPE, "application/json")]),
      Json(collection_holders),
    ).into_response()
  }

  async fn collections(params: Query<CollectionQueryParams>, State(server_config): State<ApiServerConfig>) -> impl axum::response::IntoResponse {
    //1. parse params
    let params = params.0;
    let sort_by = params.clone().sort_by.unwrap_or("biggest_on_chain_footprint".to_string());
    //2. validate params
    if ![
      "biggest_on_chain_footprint", "smallest_on_chain_footprint",
      "most_volume", "least_volume",
      "biggest_file_size", "smallest_file_size",
      "biggest_creation_fee", "smallest_creation_fee",
      "earliest_first_inscribed_date", "latest_first_inscribed_date",
      "earliest_last_inscribed_date", "latest_last_inscribed_date",
      "biggest_supply", "smallest_supply",
    ].contains(&sort_by.as_str()) {
      return (
        StatusCode::BAD_REQUEST,
        format!("Invalid sort_by: {}", sort_by),
      ).into_response();
    }
    let collections = match Self::get_collections(server_config.deadpool, params).await {
      Ok(collections) => collections,
      Err(error) => {
        log::warn!("Error getting /collections: {}", error);
        return (
          StatusCode::INTERNAL_SERVER_ERROR,
          format!("Error retrieving collections"),
        ).into_response();
      }
    };
    (
      ([(axum::http::header::CONTENT_TYPE, "application/json")]),
      Json(collections),
    ).into_response()
  }

  async fn inscription_collection_data(Path(inscription_id): Path<InscriptionId>, State(server_config): State<ApiServerConfig>) -> impl axum::response::IntoResponse {
    let collection_data = match Self::get_inscription_collection_data(server_config.deadpool, inscription_id.to_string()).await {
      Ok(collection_data) => collection_data,
      Err(error) => {
        log::warn!("Error getting /collection_data_by_inscription_id: {}", error);
        return (
          StatusCode::INTERNAL_SERVER_ERROR,
          format!("Error retrieving collection data for {}", inscription_id.to_string()),
        ).into_response();
      }    
    };
    (
      ([(axum::http::header::CONTENT_TYPE, "application/json")]),
      Json(collection_data),
    ).into_response()
  }

  async fn inscription_collection_data_number(Path(number): Path<i64>, State(server_config): State<ApiServerConfig>) -> impl axum::response::IntoResponse {
    let collection_data = match Self::get_inscription_collection_data_number(server_config.deadpool, number).await {
      Ok(collection_data) => collection_data,
      Err(error) => {
        log::warn!("Error getting /collection_data_by_inscription_number: {}", error);
        return (
          StatusCode::INTERNAL_SERVER_ERROR,
          format!("Error retrieving collection data for {}", number),
        ).into_response();
      }    
    };
    (
      ([(axum::http::header::CONTENT_TYPE, "application/json")]),
      Json(collection_data),
    ).into_response()
  }

  async fn inscriptions_in_collection(Path(collection_symbol): Path<String>, params: Query<InscriptionQueryParams>, State(server_config): State<ApiServerConfig>) -> impl axum::response::IntoResponse {
    let parsed_params = match Self::parse_and_validate_inscription_params(params.0) {
      Ok(parsed_params) => parsed_params,
      Err(error) => {
        log::warn!("Error getting /inscriptions_in_collection: {}", error);
        return (
          StatusCode::BAD_REQUEST,
          format!("Error parsing and validating params: {}", error),
        ).into_response();
      }
    };
    let inscriptions = match Self::get_inscriptions_in_collection(server_config.deadpool, collection_symbol, parsed_params).await {
      Ok(inscriptions) => inscriptions,
      Err(error) => {
        log::warn!("Error getting /inscriptions_in_collection: {}", error);
        return (
          StatusCode::INTERNAL_SERVER_ERROR,
          format!("Error retrieving inscriptions in collection"),
        ).into_response();
      }
    };
    (
      ([(axum::http::header::CONTENT_TYPE, "application/json")]),
      Json(inscriptions),
    ).into_response()
  }

  async fn block_statistics(Path(block): Path<i64>, State(server_config): State<ApiServerConfig>) -> impl axum::response::IntoResponse {
    let block_stats = match Self::get_block_statistics(server_config.deadpool, block).await {
      Ok(block_stats) => block_stats,
      Err(error) => {
        log::warn!("Error getting /block_statistics: {}", error);
        return (
          StatusCode::INTERNAL_SERVER_ERROR,
          format!("Error retrieving block statistics for {}", block),
        ).into_response();
      }    
    };
    (
      ([(axum::http::header::CONTENT_TYPE, "application/json")]),
      Json(block_stats),
    ).into_response()
  }

  async fn sat_block_statistics(Path(block): Path<i64>, State(server_config): State<ApiServerConfig>) -> impl axum::response::IntoResponse {
    let block_stats = match Self::get_sat_block_statistics(server_config.deadpool, block).await {
      Ok(block_stats) => block_stats,
      Err(error) => {
        log::warn!("Error getting /sat_block_statistics: {}", error);
        return (
          StatusCode::INTERNAL_SERVER_ERROR,
          format!("Error retrieving sat block statistics for {}", block),
        ).into_response();
      }    
    };
    (
      ([(axum::http::header::CONTENT_TYPE, "application/json")]),
      Json(block_stats),
    ).into_response()
  }

  async fn blocks(params: Query<CollectionQueryParams>, State(server_config): State<ApiServerConfig>) -> impl axum::response::IntoResponse {
    //1. parse params
    let params = params.0;
    let sort_by = params.clone().sort_by.unwrap_or("newest".to_string());
    //2. validate params
    if ![
      "newest", "oldest", 
      "most_txs", "least_txs", 
      "most_inscriptions", "least_inscriptions",
      "biggest_block", "smallest_block",
      "biggest_total_inscriptions_size", "smallest_total_inscriptions_size",
      "highest_total_fees", "lowest_total_fees",
      "highest_inscription_fees", "lowest_inscription_fees",
      "most_volume", "least_volume"].contains(&sort_by.as_str()) {
      return (
        StatusCode::BAD_REQUEST,
        format!("Invalid sort_by: {}", sort_by),
      ).into_response();
    }
    let blocks = match Self::get_blocks(server_config.deadpool, params).await {
      Ok(blocks) => blocks,
      Err(error) => {
        log::warn!("Error getting /blocks: {}", error);
        return (
          StatusCode::INTERNAL_SERVER_ERROR,
          format!("Error retrieving blocks"),
        ).into_response();
      }
    };
    (
      ([(axum::http::header::CONTENT_TYPE, "application/json")]),
      Json(blocks),
    ).into_response()
  }

  async fn search_by_query(Path(search_query): Path<String>, State(server_config): State<ApiServerConfig>) -> impl axum::response::IntoResponse {
    let search_result = match Self::get_search_result(server_config.deadpool, search_query.clone()).await {
      Ok(search_result) => search_result,
      Err(error) => {
        log::warn!("Error getting /search_by_query: {}", error);
        return (
          StatusCode::INTERNAL_SERVER_ERROR,
          format!("Error retrieving search results for {}", search_query),
        ).into_response();
      }    
    };
    (
      ([(axum::http::header::CONTENT_TYPE, "application/json")]),
      Json(search_result),
    ).into_response()
  }

  async fn block_icon(Path(block): Path<i64>, State(server_config): State<ApiServerConfig>) -> impl axum::response::IntoResponse {
    let content_blob = match Self::get_block_icon(server_config.deadpool,  block).await {
      Ok(content_blob) => content_blob,
      Err(error) => {
        log::warn!("Error getting /block_icon: {}", error);
        return (
          StatusCode::INTERNAL_SERVER_ERROR,
          format!("Error retrieving block icon {}", block.to_string()),
        ).into_response();
      }
    };
    let bytes = content_blob.content;
    let content_type = content_blob.content_type;
    (
      ([(axum::http::header::CONTENT_TYPE, content_type),
        (axum::http::header::CACHE_CONTROL, "public, max-age=31536000".to_string())]),
      bytes,
    ).into_response()
  }

  async fn sat_block_icon(Path(block): Path<i64>, State(server_config): State<ApiServerConfig>) -> impl axum::response::IntoResponse {
    let content_blob = match Self::get_sat_block_icon(server_config.deadpool,  block).await {
      Ok(content_blob) => content_blob,
      Err(error) => {
        log::warn!("Error getting /block_icon: {}", error);
        return (
          StatusCode::INTERNAL_SERVER_ERROR,
          format!("Error retrieving block icon {}", block.to_string()),
        ).into_response();
      }
    };
    let bytes = content_blob.content;
    let content_type = content_blob.content_type;
    (
      ([(axum::http::header::CONTENT_TYPE, content_type),
        (axum::http::header::CACHE_CONTROL, "public, max-age=31536000".to_string())]),
      bytes,
    ).into_response()
  }

  async fn shutdown_signal() {
    tokio::signal::ctrl_c()
        .await
        .expect("expect tokio signal ctrl-c");
  }

  //DB functions
  fn read_offchain_metadata(root_dir: &str) -> Result<(Vec<CollectionList>, Vec<Collection>)> {
    let mut meta_data_vec: Vec<CollectionList> = Vec::new();
    let mut collection_vec: Vec<Collection> = Vec::new();
    
    for entry in fs::read_dir(root_dir)? {
        let entry = entry?;
        let path = entry.path();
        //println!("Collection: {:?}", path);
        if path.is_dir() {
            let meta_file_path = path.join("meta.json");
            if meta_file_path.exists() {
              let content = fs::read_to_string(meta_file_path)?;

              let meta_data: CollectionList = match serde_json::from_str(&content) {
                  Ok(data) => data,
                  Err(e) => {
                      println!("Skipped: {:?} - {:?}", path , e);
                      continue;
                  }
              };
              //println!("Meta data: {:?}", meta_data);
              let collection_symbol = meta_data.collection_symbol.clone();
              meta_data_vec.push(meta_data);
              let inscriptions_file_path = path.join("inscriptions.json");
              if inscriptions_file_path.exists() {
                let content = fs::read_to_string(inscriptions_file_path)?;
                let mut collections: Vec<Collection> = match serde_json::from_str(&content) {
                  Ok(data) => data,
                  Err(e) => {
                      println!("Skipped: {:?} - {:?}", path , e);
                      continue;
                  }
                };
                collections.iter_mut().for_each(|collection| {
                    collection.collection_symbol = Some(collection_symbol.clone());
                });
                collection_vec.append(&mut collections);
              }
            }
        }
    }
    
    Ok((meta_data_vec, collection_vec))
}

  async fn insert_offchain_collection_data(pool: deadpool) -> anyhow::Result<()> {
    let root_directory = "../ordinals-collections/collections";
    let (collection_list, collections)  = Self::read_offchain_metadata(root_directory)?;
    Self::insert_collection_list(pool.clone(), collection_list).await?;
    Self::insert_collections(pool.clone(), collections).await?;
    Ok(())
  }

  async fn insert_collection_list(pool: deadpool, collection_list: Vec<CollectionList>) -> anyhow::Result<()> {
    let mut conn = pool.get().await?;
    let tx = conn.transaction().await?;
    tx.simple_query("CREATE TEMP TABLE inserts_collection_list ON COMMIT DROP AS TABLE collection_list WITH NO DATA").await?;
    let copy_stm = r#"COPY inserts_collection_list (
      collection_symbol,
      name,
      image_uri,
      inscription_icon,
      description,
      supply,
      twitter,
      discord,
      website,
      min_inscription_number,
      max_inscription_number,
      date_created
    ) FROM STDIN BINARY"#;
    let col_types = vec![
      Type::VARCHAR,
      Type::TEXT,
      Type::TEXT,
      Type::VARCHAR,
      Type::TEXT,
      Type::INT8,
      Type::TEXT,
      Type::TEXT,
      Type::TEXT,
      Type::INT8,
      Type::INT8,
      Type::INT8
    ];
    let sink = tx.copy_in(copy_stm).await?;
    let writer = BinaryCopyInWriter::new(sink, &col_types);
    pin_mut!(writer);
    for m in collection_list {
      let mut row: Vec<&'_ (dyn ToSql + Sync)> = Vec::new();
      row.push(&m.collection_symbol);
      row.push(&m.name);
      row.push(&m.image_uri);
      let icon_short = &m.inscription_icon.map(|s| s.chars().take(80).collect::<String>());
      row.push(icon_short);
      row.push(&m.description);
      row.push(&m.supply);
      row.push(&m.twitter);
      row.push(&m.discord);
      row.push(&m.website);
      row.push(&m.min_inscription_number);
      row.push(&m.max_inscription_number);
      row.push(&m.date_created);
      writer.as_mut().write(&row).await?;
    }  
    writer.finish().await?;
    tx.simple_query("INSERT INTO collection_list SELECT * FROM inserts_collection_list ON CONFLICT DO NOTHING").await?;
    tx.commit().await?;
    Ok(())
  }

  async fn insert_collections(pool: deadpool, collections: Vec<Collection>) -> anyhow::Result<()> {
    let mut conn = pool.get().await?;
    let tx = conn.transaction().await?;
    tx.simple_query("CREATE TEMP TABLE inserts_collections ON COMMIT DROP AS TABLE collections WITH NO DATA").await?;
    let copy_stm = r#"COPY inserts_collections (
      id,
      number,
      collection_symbol,
      off_chain_metadata
    ) FROM STDIN BINARY"#;
    let col_types = vec![
      Type::VARCHAR,
      Type::INT8,
      Type::VARCHAR,
      Type::JSONB
    ];
    let sink = tx.copy_in(copy_stm).await?;
    let writer = BinaryCopyInWriter::new(sink, &col_types);
    pin_mut!(writer);
    for m in collections {
      let mut row: Vec<&'_ (dyn ToSql + Sync)> = Vec::new();
      row.push(&m.id);
      row.push(&m.number);
      row.push(&m.collection_symbol);
      row.push(&m.off_chain_metadata);
      writer.as_mut().write(&row).await?;
    }
    writer.finish().await?;
    tx.simple_query("INSERT INTO collections SELECT * FROM inserts_collections ON CONFLICT DO NOTHING").await?;
    tx.commit().await?;
    Ok(())
  }

  async fn get_ordinal_content(pool: deadpool, inscription_id: String) -> anyhow::Result<ContentBlob> {
    let conn = pool.clone().get().await?;
    let row = conn.query_one(
      "SELECT sha256, content_type, content_encoding, delegate FROM ordinals WHERE id=$1 LIMIT 1",
      &[&inscription_id]
    ).await?;
    let mut sha256: Option<String> = row.get(0);
    let mut content_type: Option<String> = row.get(1);
    let mut content_encoding: Option<String> = row.get(2);
    let delegate: Option<String> = row.get(3);
    match delegate {
      Some(delegate) => {
        let id: Regex = Regex::new(r"^[[:xdigit:]]{64}i\d+$").unwrap();
        if id.is_match(&delegate) {
          let row = conn.query_one(
            "SELECT sha256, content_type, content_encoding FROM ordinals WHERE id=$1 LIMIT 1",
            &[&delegate]
          ).await?;
          sha256 = row.get(0);
          content_type = row.get(1);
          content_encoding = row.get(2);
        }
      },
      None => {}
    }
    let sha256 = sha256.ok_or(anyhow!("No sha256 found"))?;
    let content = Self::get_ordinal_content_by_sha256(pool, sha256, content_type, content_encoding).await;
    content
  }

  async fn get_ordinal_content_by_number(pool: deadpool, number: i64) -> anyhow::Result<ContentBlob> {
    let conn = pool.clone().get().await?;
    let row = conn.query_one(
      "SELECT sha256, content_type, content_encoding, delegate FROM ordinals WHERE number=$1 LIMIT 1",
      &[&number]
    ).await?;
    let mut sha256: Option<String> = row.get(0);
    let mut content_type: Option<String> = row.get(1);
    let mut content_encoding: Option<String> = row.get(2);
    let delegate: Option<String> = row.get(3);
    match delegate {
      Some(delegate) => {
        let id: Regex = Regex::new(r"^[[:xdigit:]]{64}i\d+$").unwrap();
        if id.is_match(&delegate) {
          let row = conn.query_one(
            "SELECT sha256, content_type, content_encoding  FROM ordinals WHERE id=$1 LIMIT 1",
            &[&delegate]
          ).await?;
          sha256 = row.get(0);
          content_type = row.get(1);
          content_encoding = row.get(2);
        }
      },
      None => {}
    }
    let sha256 = sha256.ok_or(anyhow!("No sha256 found"))?;
    let content = Self::get_ordinal_content_by_sha256(pool, sha256, content_type, content_encoding).await;
    content
  }

  async fn get_ordinal_content_by_sha256(pool: deadpool, sha256: String, content_type_override: Option<String>, content_encoding_override: Option<String>) -> anyhow::Result<ContentBlob> {
    let conn = pool.get().await?;
    let moderation_flag = match conn.query_one(
      r"SELECT coalesce(human_override_moderation_flag, automated_moderation_flag)
              FROM content_moderation
              WHERE sha256=$1
              LIMIT 1",
      &[&sha256]
    ).await {
      Ok(row) => row,
      Err(_) => {
        let content = ContentBlob {
          sha256: "NOT_INDEXED".to_string(),
          content: "This content hasn't been indexed yet.".as_bytes().to_vec(),
          content_type: "text/plain;charset=utf-8".to_string(),
          content_encoding: None
        };
        return Ok(content);
      }
    };
    let moderation_flag: Option<String> = moderation_flag.get(0);
    let flag = moderation_flag.ok_or(anyhow!("No moderation flag found"))?;
    if flag == "SAFE_MANUAL" || flag == "SAFE_AUTOMATED" || flag == "UNKNOWN_AUTOMATED" {
        //Proceed as normal
    } else {
      let content = ContentBlob {
          sha256: sha256.clone(),
          content: std::fs::read("blocked.png")?,
          content_type: "image/png".to_string(),
          content_encoding: None
      };
      return Ok(content);
    }

    //Proceed if safe
    let row = conn.query_one(
      r"SELECT *
              FROM content
              WHERE sha256=$1
              LIMIT 1",
      &[&sha256]
    ).await?;
    let mut content_blob = ContentBlob {
      sha256: row.get("sha256"),
      content: row.get("content"),
      content_type: row.get("content_type"),
      content_encoding: row.get("content_encoding")
    };
    if let Some(content_type) = content_type_override {
      content_blob.content_type = content_type;
    }
    content_blob.content_encoding = content_encoding_override;
    Ok(content_blob)
  }

  async fn get_block_icon(pool: deadpool, block: i64) -> anyhow::Result<ContentBlob> {
    let conn = pool.get().await?;
    let result = conn.query_one(
      "select id from ordinals where genesis_height=$1 and (content_type LIKE 'image%' or content_type LIKE 'text/html%') order by content_length desc nulls last limit 1", 
      &[&block]
    ).await?;
    let id = result.get(0);
    let content = Self::get_ordinal_content(pool, id).await?;
    Ok(content)
  }

  async fn get_sat_block_icon(pool: deadpool, block: i64) -> anyhow::Result<ContentBlob> {
    let conn = pool.get().await?;
    let result = conn.query_one(
      "select id from ordinals where sat in (select sat from sat where block=$1) and (content_type LIKE 'image%' or content_type LIKE 'text/html%') order by content_length desc nulls last limit 1", 
      &[&block]
    ).await?;
    let id = result.get(0);
    let content = Self::get_ordinal_content(pool, id).await?;
    Ok(content)
  }

  fn map_row_to_metadata(row: tokio_postgres::Row) -> Metadata {
    Metadata {
      id: row.get("id"),
      content_length: row.get("content_length"),
      content_type: row.get("content_type"), 
      content_encoding: row.get("content_encoding"),
      content_category: row.get("content_category"),
      genesis_fee: row.get("genesis_fee"),
      genesis_height: row.get("genesis_height"),
      genesis_transaction: row.get("genesis_transaction"),
      pointer: row.get("pointer"),
      number: row.get("number"),
      sequence_number: row.get("sequence_number"),
      parents: row.get("parents"),
      delegate: row.get("delegate"),
      metaprotocol: row.get("metaprotocol"),
      on_chain_metadata: row.get("on_chain_metadata"),
      sat: row.get("sat"),
      sat_block: row.get("sat_block"),
      satributes: row.get("satributes"),
      charms: row.get("charms"),
      timestamp: row.get("timestamp"),
      sha256: row.get("sha256"),
      text: row.get("text"),
      referenced_ids: row.get("referenced_ids"),
      is_json: row.get("is_json"),
      is_maybe_json: row.get("is_maybe_json"),
      is_bitmap_style: row.get("is_bitmap_style"),
      is_recursive: row.get("is_recursive")
    }
  }

  fn map_row_to_fullmetadata(row: tokio_postgres::Row) -> FullMetadata {
    FullMetadata {
      id: row.get("id"),
      content_length: row.get("content_length"),
      content_type: row.get("content_type"), 
      content_encoding: row.get("content_encoding"),
      content_category: row.get("content_category"),
      genesis_fee: row.get("genesis_fee"),
      genesis_height: row.get("genesis_height"),
      genesis_transaction: row.get("genesis_transaction"),
      pointer: row.get("pointer"),
      number: row.get("number"),
      sequence_number: row.get("sequence_number"),
      parents: row.get("parents"),
      delegate: row.get("delegate"),
      metaprotocol: row.get("metaprotocol"),
      on_chain_metadata: row.get("on_chain_metadata"),
      sat: row.get("sat"),
      sat_block: row.get("sat_block"),
      satributes: row.get("satributes"),
      charms: row.get("charms"),
      timestamp: row.get("timestamp"),
      sha256: row.get("sha256"),
      text: row.get("text"),
      referenced_ids: row.get("referenced_ids"),
      is_json: row.get("is_json"),
      is_maybe_json: row.get("is_maybe_json"),
      is_bitmap_style: row.get("is_bitmap_style"),
      is_recursive: row.get("is_recursive"),
      collection_symbol: row.get("collection_symbol"),
      off_chain_metadata: row.get("off_chain_metadata"),      
      collection_name: row.get("collection_name"),
    }
  }

  async fn get_ordinal_metadata(pool: deadpool, inscription_id: String) -> anyhow::Result<FullMetadata> {
    let conn = pool.get().await?;
    let result = conn.query_one(
      "SELECT * FROM ordinals_full_v where id=$1 LIMIT 1", 
      &[&inscription_id]
    ).await?;
    Ok(Self::map_row_to_fullmetadata(result))
  }

  async fn get_ordinal_metadata_by_number(pool: deadpool, number: i64) -> anyhow::Result<FullMetadata> {
    let conn = pool.get().await?;
    let result = conn.query_one(
      "SELECT * FROM ordinals_full_v where number=$1 LIMIT 1", 
      &[&number]
    ).await?;
    Ok(Self::map_row_to_fullmetadata(result))
  }

  async fn get_inscription_edition(pool: deadpool, inscription_id: String) -> anyhow::Result<InscriptionNumberEdition> {
    let conn = pool.get().await?;
    let result = conn.query_one(
      "select e.*, t.total from editions e left join editions_total t on e.sha256=t.sha256 where e.id=$1",
      &[&inscription_id]
    ).await?;
    let edition = InscriptionNumberEdition {
      id: result.get("id"),
      number: result.get("number"),
      edition: result.get("edition"),
      total: result.get("total")
    };
    Ok(edition)
  }

  async fn get_inscription_edition_number(pool: deadpool, number: i64) -> anyhow::Result<InscriptionNumberEdition> {
    let conn = pool.get().await?;
    let result = conn.query_one(
      "select e.*, t.total from editions e left join editions_total t on e.sha256=t.sha256 where e.number=$1",
      &[&number]
    ).await?;
    let edition = InscriptionNumberEdition {
      id: result.get("id"),
      number: result.get("number"),
      edition: result.get("edition"),
      total: result.get("total")
    };
    Ok(edition)
  }

  async fn get_matching_inscriptions_by_sha256(pool: deadpool, sha256: String, params: PaginationParams) -> anyhow::Result<Vec<InscriptionNumberEdition>> {
    let conn = pool.get().await?;
    let page_size = params.page_size.unwrap_or(10);
    let offset = params.page_number.unwrap_or(0) * page_size;
    let mut query = "SELECT id, number, edition, t.total from (select * from editions where sha256=$1) e inner join editions_total t on t.sha256=e.sha256 order by edition asc".to_string();
    if page_size > 0 {
      query.push_str(format!(" LIMIT {}", page_size).as_str());
    }
    if offset > 0 {
      query.push_str(format!(" OFFSET {}", offset).as_str());
    }
    let result = conn.query(
      query.as_str(),
      &[&sha256]
    ).await?;
    let mut editions = Vec::new();
    for row in result {
      editions.push(InscriptionNumberEdition {
        id: row.get("id"),
        number: row.get("number"),
        edition: row.get("edition"),
        total: row.get("total")
      });
    }
    Ok(editions)
  }

  async fn get_inscription_children(pool: deadpool, inscription_id: String, params: PaginationParams) -> anyhow::Result<Vec<FullMetadata>> {
    let conn = pool.get().await?;
    let page_size = params.page_size.unwrap_or(10);
    let offset = params.page_number.unwrap_or(0) * page_size;
    let mut query = "SELECT * FROM ordinals_full_v WHERE parents && ARRAY[$1::varchar]".to_string();
    if page_size > 0 {
      query.push_str(format!(" LIMIT {}", page_size).as_str());
    }
    if offset > 0 {
      query.push_str(format!(" OFFSET {}", offset).as_str());
    }
    let result = conn.query(
      query.as_str(), 
      &[&inscription_id]
    ).await?;
    let mut inscriptions = Vec::new();
    for row in result {
      inscriptions.push(Self::map_row_to_fullmetadata(row));
    }
    Ok(inscriptions)
  }

  async fn get_inscription_children_by_number(pool: deadpool, number: i64, params: PaginationParams) -> anyhow::Result<Vec<FullMetadata>> {
    let conn = pool.get().await?;
    let query = "Select id from ordinals where number=$1";
    let result = conn.query_one(
      query, 
      &[&number]
    ).await?;
    let id: String = result.get(0);
    let inscriptions = Self::get_inscription_children(pool, id, params).await;
    inscriptions
  }

  async fn get_inscription_referenced_by(pool: deadpool, inscription_id: String, params: PaginationParams) -> anyhow::Result<Vec<FullMetadata>> {
    let conn = pool.get().await?;
    let page_size = params.page_size.unwrap_or(10);
    let offset = params.page_number.unwrap_or(0) * page_size;
    let mut query = "SELECT * FROM ordinals_full_v WHERE referenced_ids && ARRAY[$1::varchar]".to_string();
    if page_size > 0 {
      query.push_str(format!(" LIMIT {}", page_size).as_str());
    }
    if offset > 0 {
      query.push_str(format!(" OFFSET {}", offset).as_str());
    }
    let result = conn.query(
      query.as_str(), 
      &[&inscription_id]
    ).await?;
    let mut inscriptions = Vec::new();
    for row in result {
      inscriptions.push(Self::map_row_to_fullmetadata(row));
    }
    Ok(inscriptions)
  }

  async fn get_inscription_referenced_by_number(pool: deadpool, number: i64, params: PaginationParams) -> anyhow::Result<Vec<FullMetadata>> {
    let conn = pool.get().await?;
    let query = "Select id from ordinals where number=$1";
    let result = conn.query_one(
      query, 
      &[&number]
    ).await?;
    let id: String = result.get(0);
    let inscriptions = Self::get_inscription_referenced_by(pool, id, params).await;
    inscriptions
  }

  async fn get_inscriptions_within_block(pool: deadpool, block: i64, params: ParsedInscriptionQueryParams) -> anyhow::Result<Vec<FullMetadata>> {
    let conn = pool.get().await?;
    let base_query = "SELECT * FROM ordinals_full_v o WHERE genesis_height=$1".to_string();
    let full_query = Self::create_inscription_query_string(base_query, params);
    println!("{}", full_query);
    let result = conn.query(
      full_query.as_str(), 
      &[&block]
    ).await?;
    let mut inscriptions = Vec::new();
    for row in result {
      inscriptions.push(Self::map_row_to_fullmetadata(row));
    }
    Ok(inscriptions)
  }
  
  async fn get_random_inscription(pool: deadpool, random_float: f64) -> anyhow::Result<(FullMetadata, (f64, f64))> {
    let conn = pool.get().await?;
    let random_inscription_band = conn.query_one(
      "SELECT first_number, class_band_start, class_band_end FROM weights where band_end>$1 order by band_end limit 1",
      &[&random_float]
    ).await?;
    let random_inscription_band = RandomInscriptionBand {
      sequence_number: random_inscription_band.get("first_number"),
      start: random_inscription_band.get("class_band_start"),
      end: random_inscription_band.get("class_band_end")
    };
    let metadata = conn.query_one(
      "SELECT * from ordinals_full_v where sequence_number=$1 limit 1", 
      &[&random_inscription_band.sequence_number]
    ).await?;
    let metadata = Self::map_row_to_fullmetadata(metadata);
    Ok((metadata,(random_inscription_band.start, random_inscription_band.end)))
  }

  async fn get_random_inscriptions(pool: deadpool, n: u32, mut bands: Vec<(f64, f64)>) -> anyhow::Result<(Vec<FullMetadata>, Vec<(f64, f64)>)> {
    let n = std::cmp::min(n, 100);
    let mut rng = rand::rngs::StdRng::from_entropy();
    let mut random_floats = Vec::new();
    while random_floats.len() < n as usize {
      let random_float = rng.gen::<f64>();
      let mut already_seen = false;
      for band in bands.iter() {
        if random_float >= band.0 && random_float < band.1 {
          already_seen = true;
          break;
        }
      }
      if !already_seen {
        random_floats.push(random_float);
      }
    }

    let mut set = JoinSet::new();
    let mut random_metadatas = Vec::new();
    for i in 0..n {
      set.spawn(Self::get_random_inscription(pool.clone(), random_floats[i as usize]));
    }
    while let Some(res) = set.join_next().await {
      let random_inscription_details = res??;
      random_metadatas.push(random_inscription_details.0);
      bands.push(random_inscription_details.1);
    }
    Ok((random_metadatas, bands))
  }

  async fn get_recent_inscriptions(pool: deadpool, n: u32) -> anyhow::Result<Vec<FullMetadata>> {
    let conn = pool.get().await?;
    let result = conn.query(
      "SELECT * FROM ordinals_full_v order by sequence_number desc limit $1", 
      &[&n]
    ).await?;
    let mut inscriptions = Vec::new();
    for row in result {
      inscriptions.push(Self::map_row_to_fullmetadata(row));
    }
    Ok(inscriptions)
  }

  fn create_inscription_query_string(base_query: String, params: ParsedInscriptionQueryParams) -> String {
    let mut query = base_query;
    if params.content_types.len() > 0 {
      query.push_str(" AND (");
      for (i, content_type) in params.content_types.iter().enumerate() {
        if content_type == "text" {
          query.push_str("o.content_category = 'text'");
        } else if content_type == "image" {
          query.push_str("o.content_category = 'image'");
        } else if content_type == "gif" {
          query.push_str("o.content_category = 'gif'");
        } else if content_type == "audio" {
          query.push_str("o.content_category = 'audio'");
        } else if content_type == "video" {
          query.push_str("o.content_category = 'video'");
        } else if content_type == "html" {
          query.push_str("o.content_category = 'html'");
        } else if content_type == "json" {
          query.push_str("o.content_category = 'json'");
        } else if content_type == "namespace" {
          query.push_str("o.content_category = 'namespace'");
        } else if content_type == "javascript" {
          query.push_str("o.content_category = 'javascript'");
        }
        if i < params.content_types.len() - 1 {
          query.push_str(" OR ");
        }
      }
      query.push_str(")");
    }
    if params.satributes.len() > 0 {
      query.push_str(format!(" AND (o.satributes && array['{}'::varchar])", params.satributes.join("'::varchar,'")).as_str());
    }
    if params.charms.len() > 0 {
      query.push_str(format!(" AND (o.charms && array['{}'::varchar])", params.charms.join("'::varchar,'")).as_str());
    }
    if params.sort_by == "newest" {
      query.push_str(" ORDER BY o.sequence_number DESC");
    } else if params.sort_by == "oldest" {
      query.push_str(" ORDER BY o.sequence_number ASC");
    } else if params.sort_by == "newest_sat" {
      query.push_str(" ORDER BY o.sat DESC");
    } else if params.sort_by == "oldest_sat" {
      query.push_str(" ORDER BY o.sat ASC");
    } else if params.sort_by == "rarest_sat" {
      //query.push_str(" ORDER BY o.sat ASC");
    } else if params.sort_by == "commonest_sat" {
      //query.push_str(" ORDER BY o.sat DESC");
    } else if params.sort_by == "biggest" {
      query.push_str(" ORDER BY o.content_length DESC");
    } else if params.sort_by == "smallest" {
      query.push_str(" ORDER BY o.content_length ASC");
    } else if params.sort_by == "highest_fee" {
      query.push_str(" ORDER BY o.genesis_fee DESC");
    } else if params.sort_by == "lowest_fee" {
      query.push_str(" ORDER BY o.genesis_fee ASC");
    }
    if params.page_size > 0 {
      query.push_str(format!(" LIMIT {}", params.page_size).as_str());
    }
    if params.page_number > 0 {
      query.push_str(format!(" OFFSET {}", params.page_number * params.page_size).as_str());
    }
    query
  }

  async fn get_inscriptions(pool: deadpool, params: ParsedInscriptionQueryParams) -> anyhow::Result<Vec<FullMetadata>> {
    let conn = pool.get().await?;
    //1. build query
    let mut query = "SELECT o.* FROM ordinals_full_v o WHERE 1=1".to_string();
    if params.content_types.len() > 0 {
      query.push_str(" AND (");
      for (i, content_type) in params.content_types.iter().enumerate() {
        if content_type == "text" {
          query.push_str("o.content_category = 'text'");
        } else if content_type == "image" {
          query.push_str("o.content_category = 'image'");
        } else if content_type == "gif" {
          query.push_str("o.content_category = 'gif'");
        } else if content_type == "audio" {
          query.push_str("o.content_category = 'audio'");
        } else if content_type == "video" {
          query.push_str("o.content_category = 'video'");
        } else if content_type == "html" {
          query.push_str("o.content_category = 'html'");
        } else if content_type == "json" {
          query.push_str("o.content_category = 'json'");
        } else if content_type == "namespace" {
          query.push_str("o.content_category = 'namespace'");
        } else if content_type == "javascript" {
          query.push_str("o.content_category = 'javascript'");
        }
        if i < params.content_types.len() - 1 {
          query.push_str(" OR ");
        }
      }
      query.push_str(")");
    }
    if params.satributes.len() > 0 {
      query.push_str(format!(" AND (o.satributes && array['{}'::varchar])", params.satributes.join("'::varchar,'")).as_str());
    }
    if params.charms.len() > 0 {
      query.push_str(format!(" AND (o.charms && array['{}'::varchar])", params.charms.join("'::varchar,'")).as_str());
    }
    if params.sort_by == "newest" {
      query.push_str(" ORDER BY o.sequence_number DESC");
    } else if params.sort_by == "oldest" {
      query.push_str(" ORDER BY o.sequence_number ASC");
    } else if params.sort_by == "newest_sat" {
      query.push_str(" ORDER BY o.sat DESC");
    } else if params.sort_by == "oldest_sat" {
      query.push_str(" ORDER BY o.sat ASC");
    } else if params.sort_by == "rarest_sat" {
      //query.push_str(" ORDER BY o.sat ASC");
    } else if params.sort_by == "commonest_sat" {
      //query.push_str(" ORDER BY o.sat DESC");
    } else if params.sort_by == "biggest" {
      query.push_str(" ORDER BY o.content_length DESC");
    } else if params.sort_by == "smallest" {
      query.push_str(" ORDER BY o.content_length ASC");
    } else if params.sort_by == "highest_fee" {
      query.push_str(" ORDER BY o.genesis_fee DESC");
    } else if params.sort_by == "lowest_fee" {
      query.push_str(" ORDER BY o.genesis_fee ASC");
    }
    if params.page_size > 0 {
      query.push_str(format!(" LIMIT {}", params.page_size).as_str());
    }
    if params.page_number > 0 {
      query.push_str(format!(" OFFSET {}", params.page_number * params.page_size).as_str());
    }
    println!("Query: {}", query);
    let result = conn.query(
      query.as_str(), 
      &[]
    ).await?;
    let mut inscriptions = Vec::new();
    for row in result {
      inscriptions.push(Self::map_row_to_fullmetadata(row));
    }
    Ok(inscriptions)
  }

  async fn get_deadpool(settings: Settings) -> anyhow::Result<deadpool> {
    let mut deadpool_cfg = deadpool_postgres::Config::new();
    deadpool_cfg.host = settings.db_host().map(|s| s.to_string());
    deadpool_cfg.dbname = settings.db_name().map(|s| s.to_string());
    deadpool_cfg.user = settings.db_user().map(|s| s.to_string());
    deadpool_cfg.password = settings.db_password().map(|s| s.to_string());
    deadpool_cfg.manager = Some(ManagerConfig { recycling_method: RecyclingMethod::Fast });
    let deadpool = deadpool_cfg.create_pool(Some(deadpool_postgres::Runtime::Tokio1), NoTls)?;
    Ok(deadpool)
  }

  async fn get_last_ordinal_transfer(pool: deadpool, inscription_id: String) -> anyhow::Result<Transfer> {
    let conn = pool.get().await?;
    let result = conn.query_one(
      "SELECT * FROM transfers WHERE id=$1 ORDER BY block_number DESC LIMIT 1", 
      &[&inscription_id]
    ).await?;
    let transfer = Transfer {
      id: result.get("id"),
      block_number: result.get("block_number"),
      block_timestamp: result.get("block_timestamp"),
      satpoint: result.get("satpoint"),
      tx_offset: result.get("tx_offset"),
      transaction: result.get("transaction"),
      vout: result.get("vout"),
      offset: result.get("satpoint_offset"),
      address: result.get("address"),
      previous_address: result.get("previous_address"),
      price: result.get("price"),
      tx_fee: result.get("tx_fee"),
      tx_size: result.get("tx_size"),
      is_genesis: result.get("is_genesis")
    };
    Ok(transfer)
  }

  async fn get_last_ordinal_transfer_by_number(pool: deadpool, number: i64) -> anyhow::Result<Transfer> {
    let conn = pool.get().await?;
    let result = conn.query_one(
      "with a as (Select id from ordinals where number=$1) select b.* from transfers b, a where a.id=b.id order by block_number desc limit 1", 
      &[&number]
    ).await?;
    let transfer = Transfer {
      id: result.get("id"),
      block_number: result.get("block_number"),
      block_timestamp: result.get("block_timestamp"),
      satpoint: result.get("satpoint"),
      tx_offset: result.get("tx_offset"),
      transaction: result.get("transaction"),
      vout: result.get("vout"),
      offset: result.get("satpoint_offset"),
      address: result.get("address"),
      previous_address: result.get("previous_address"),
      price: result.get("price"),
      tx_fee: result.get("tx_fee"),
      tx_size: result.get("tx_size"),
      is_genesis: result.get("is_genesis")
    };
    Ok(transfer)
  }

  async fn get_ordinal_transfers(pool: deadpool, inscription_id: String) -> anyhow::Result<Vec<Transfer>> {
    let conn = pool.get().await?;
    let result = conn.query(
      "SELECT * FROM transfers WHERE id=$1 ORDER BY block_number ASC", 
      &[&inscription_id]
    ).await?;
    let mut transfers = Vec::new();
    for row in result {
      transfers.push(Transfer {
        id: row.get("id"),
        block_number: row.get("block_number"),
        block_timestamp: row.get("block_timestamp"),
        satpoint: row.get("satpoint"),
        tx_offset: row.get("tx_offset"),
        transaction: row.get("transaction"),
        vout: row.get("vout"),
        offset: row.get("satpoint_offset"),
        address: row.get("address"),
        previous_address: row.get("previous_address"),
        price: row.get("price"),
        tx_fee: row.get("tx_fee"),
        tx_size: row.get("tx_size"),
        is_genesis: row.get("is_genesis")
      });
    }
    Ok(transfers)
  }

  async fn get_ordinal_transfers_by_number(pool: deadpool, number: i64) -> anyhow::Result<Vec<Transfer>> {
    let conn = pool.get().await?;
    let result = conn.query(
      "with a as (Select id from ordinals where number=$1) select b.* from transfers b, a where a.id=b.id order by block_number desc", 
      &[&number]
    ).await?;
    let mut transfers = Vec::new();
    for row in result {
      transfers.push(Transfer {
        id: row.get("id"),
        block_number: row.get("block_number"),
        block_timestamp: row.get("block_timestamp"),
        satpoint: row.get("satpoint"),
        tx_offset: row.get("tx_offset"),
        transaction: row.get("transaction"),
        vout: row.get("vout"),
        offset: row.get("satpoint_offset"),
        address: row.get("address"),
        previous_address: row.get("previous_address"),
        price: row.get("price"),
        tx_fee: row.get("tx_fee"),
        tx_size: row.get("tx_size"),
        is_genesis: row.get("is_genesis")
      });
    }
    Ok(transfers)
  }

  async fn get_inscriptions_by_address(pool: deadpool, address: String, params: ParsedInscriptionQueryParams) -> anyhow::Result<Vec<TransferWithMetadata>> {
    let conn = pool.get().await?;
    let base_query = "SELECT a.*, o.* FROM addresses a LEFT JOIN ordinals o ON a.id=o.id WHERE a.address=$1".to_string();
    let full_query = Self::create_inscription_query_string(base_query, params);
    let result = conn.query(
      full_query.as_str(), 
      &[&address]
    ).await?;
    let mut transfers = Vec::new();
    for row in result {
      transfers.push(TransferWithMetadata {
        id: row.get("id"),
        block_number: row.get("block_number"),
        block_timestamp: row.get("block_timestamp"),
        satpoint: row.get("satpoint"),
        tx_offset: row.get("tx_offset"),
        transaction: row.get("transaction"),
        vout: row.get("vout"),
        offset: row.get("satpoint_offset"),
        address: row.get("address"),
        is_genesis: row.get("is_genesis"),
        content_length: row.get("content_length"),
        content_type: row.get("content_type"),
        content_encoding: row.get("content_encoding"),
        content_category: row.get("content_category"),
        genesis_fee: row.get("genesis_fee"),
        genesis_height: row.get("genesis_height"),
        genesis_transaction: row.get("genesis_transaction"),
        pointer: row.get("pointer"),
        number: row.get("number"),
        sequence_number: row.get("sequence_number"),
        parents: row.get("parents"),
        delegate: row.get("delegate"),
        metaprotocol: row.get("metaprotocol"),
        on_chain_metadata: row.get("on_chain_metadata"),
        sat: row.get("sat"),
        sat_block: row.get("sat_block"),
        satributes: row.get("satributes"),
        charms: row.get("charms"),
        timestamp: row.get("timestamp"),
        sha256: row.get("sha256"),
        text: row.get("text"),
        referenced_ids: row.get("referenced_ids"),
        is_json: row.get("is_json"),
        is_maybe_json: row.get("is_maybe_json"),
        is_bitmap_style: row.get("is_bitmap_style"),
        is_recursive: row.get("is_recursive")
      });
    }
    Ok(transfers)
  }

  async fn get_inscriptions_on_sat(pool: deadpool, sat: i64) -> anyhow::Result<Vec<FullMetadata>> {
    let conn = pool.get().await?;
    let result = conn.query(
      "SELECT * FROM ordinals_full_v WHERE sat=$1", 
      &[&sat]
    ).await?;
    let mut inscriptions = Vec::new();
    for row in result {
      inscriptions.push(Self::map_row_to_fullmetadata(row));
    }
    Ok(inscriptions)
  }

  async fn get_inscriptions_in_sat_block(pool: deadpool, block: i64, params: ParsedInscriptionQueryParams) -> anyhow::Result<Vec<FullMetadata>> {
    let conn = pool.get().await?;
    let base_query = "select o.* from ordinals_full_v o where o.sat_block=$1".to_string();
    let full_query = Self::create_inscription_query_string(base_query, params);
    let result = conn.query(
      full_query.as_str(), 
      &[&block]
    ).await?;
    let mut inscriptions = Vec::new();
    for row in result {
      inscriptions.push(Self::map_row_to_fullmetadata(row));
    }
    Ok(inscriptions)
  }

  async fn get_sat_metadata(pool: deadpool, sat: i64) -> anyhow::Result<SatMetadata> {
    let conn = pool.get().await?;
    let result = conn.query_one(
      "SELECT * FROM sat WHERE sat=$1 limit 1", 
      &[&sat]
    ).await;
    let sat_metadata = match result {
      Ok(result) => {
        SatMetadata {
          sat: result.get("sat"),
          satributes: result.get("satributes"),
          decimal: result.get("sat_decimal"),
          degree: result.get("degree"),
          name: result.get("name"),
          block: result.get("block"),
          cycle: result.get("cycle"),
          epoch: result.get("epoch"),
          period: result.get("period"),
          third: result.get("third"),
          rarity: result.get("rarity"),
          percentile: result.get("percentile"),
          timestamp: result.get("timestamp")
        }      
      },
      Err(_) => {
        let parsed_sat = Sat(sat as u64);
        let mut satributes = parsed_sat.block_rarities().iter().map(|x| x.to_string()).collect::<Vec<String>>();
        let sat_rarity = parsed_sat.rarity();
        if sat_rarity != Rarity::Common {
          satributes.push(sat_rarity.to_string()); 
        }
        let mut metadata = SatMetadata {
          sat: sat.try_into().unwrap(),
          satributes: satributes,
          decimal: parsed_sat.decimal().to_string(),
          degree: parsed_sat.degree().to_string(),
          name: parsed_sat.name(),
          block: parsed_sat.height().0 as i64,
          cycle: parsed_sat.cycle() as i64,
          epoch: parsed_sat.epoch().0 as i64,
          period: parsed_sat.period() as i64,
          third: parsed_sat.third() as i64,
          rarity: parsed_sat.rarity().to_string(),
          percentile: parsed_sat.percentile(),
          timestamp: 0
        };
        let blockstats_result = conn.query_one(
          "Select * from blockstats where block_number=$1 limit 1", 
          &[&metadata.block]
        ).await?;
        metadata.timestamp = blockstats_result.get("block_timestamp");
        metadata.timestamp = metadata.timestamp/1000; //hack bug fix
        metadata
      }
    };
    Ok(sat_metadata)
  }

  async fn get_satributes(pool: deadpool, sat: i64) -> anyhow::Result<Vec<Satribute>> {
    let conn = pool.get().await?;
    let result = conn.query(
      "SELECT * FROM satributes WHERE sat=$1", 
      &[&sat]
    ).await?;
    let mut satributes = Vec::new();
    for row in result {
      satributes.push(Satribute {
        sat: row.get("sat"),
        satribute: row.get("satribute"),
      });
    }
    if satributes.len() == 0 {
      let parsed_sat = Sat(sat as u64);
      for block_rarity in parsed_sat.block_rarities().iter() {
        let satribute = Satribute {
          sat: sat as i64,
          satribute: block_rarity.to_string()
        };
        satributes.push(satribute);
      }
    }
    Ok(satributes)
  }

  async fn get_collection_summary(pool: deadpool, collection_symbol: String) -> anyhow::Result<CollectionSummary> {
    let conn = pool.get().await?;
    let query = r"
      SELECT 
        l.collection_symbol, l.name, l.description, l.twitter, l.discord, l.website,
        s.total_inscription_fees,
        s.total_inscription_size,
        s.first_inscribed_date,
        s.last_inscribed_date,
        s.supply,
        s.range_start,
        s.range_end,
        s.total_volume,
        s.total_fees,
        s.total_on_chain_footprint
      from collection_list l left join collection_summary s on l.collection_symbol=s.collection_symbol WHERE s.collection_symbol=$1 LIMIT 1";
    let result = conn.query_one(
      query, 
      &[&collection_symbol]
    ).await?;
    let collection = CollectionSummary {
      collection_symbol: result.get("collection_symbol"),
      name: result.get("name"),
      description: result.get("description"),
      twitter: result.get("twitter"),
      discord: result.get("discord"),
      website: result.get("website"),
      total_inscription_fees: result.get("total_inscription_fees"),
      total_inscription_size: result.get("total_inscription_size"),
      first_inscribed_date: result.get("first_inscribed_date"),
      last_inscribed_date: result.get("last_inscribed_date"),
      supply: result.get("supply"),
      range_start: result.get("range_start"),
      range_end: result.get("range_end"),
      total_volume: result.get("total_volume"),
      total_fees: result.get("total_fees"),
      total_on_chain_footprint: result.get("total_on_chain_footprint")
    };
    Ok(collection)
  }

  async fn get_collection_holders(pool: deadpool, collection_symbol: String, params: PaginationParams) -> anyhow::Result<Vec<CollectionHolders>> {
    let conn = pool.get().await?;
    let page_size = params.page_size.unwrap_or(10);
    let offset = params.page_number.unwrap_or(0) * page_size;
    let mut query = r"
      select 
        collection_symbol, 
        COUNT(address) OVER () AS collection_holder_count, 
        address, 
        count(*) as address_count
      from collections c 
      left join addresses a 
      on c.id = a.id 
      where c.collection_symbol = $1 
      group by a.address, c.collection_symbol 
      order by count(*) desc".to_string();
    if page_size > 0 {
      query.push_str(format!(" LIMIT {}", page_size).as_str());        
    }
    if offset > 0 {
      query.push_str(format!(" OFFSET {}", offset).as_str());
    }
    
    let result = conn.query(
      query.as_str(), 
      &[&collection_symbol]
    ).await?;
    let mut holders = Vec::new();
    for row in result {
      let holder = CollectionHolders {
        collection_symbol: row.get("collection_symbol"),
        collection_holder_count: row.get("collection_holder_count"),
        address: row.get("address"),
        address_count: row.get("address_count")
      };
      holders.push(holder);
    }
    Ok(holders)
  }

  async fn get_collections(pool: deadpool, params: CollectionQueryParams) -> anyhow::Result<Vec<CollectionSummary>> {
    let conn = pool.get().await?;
    let sort_by = params.sort_by.unwrap_or("oldest".to_string());
    let page_size = std::cmp::min(params.page_size.unwrap_or(20), 100);
    let page_number = params.page_number.unwrap_or(0);
    //1. build query
    let mut query = r"
      SELECT 
        l.collection_symbol, l.name, l.description, l.twitter, l.discord, l.website,
        s.total_inscription_fees,
        s.total_inscription_size,
        s.first_inscribed_date,
        s.last_inscribed_date,
        s.supply,
        s.range_start,
        s.range_end,
        s.total_volume,
        s.total_fees,
        s.total_on_chain_footprint
      from collection_list l left join collection_summary s on l.collection_symbol=s.collection_symbol where l.name!=''".to_string();
    if sort_by == "biggest_on_chain_footprint" {
      query.push_str(" ORDER BY s.total_on_chain_footprint DESC NULLS LAST");
    } else if sort_by == "smallest_on_chain_footprint" {
      query.push_str(" ORDER BY s.total_on_chain_footprint ASC");
    } else if sort_by == "most_volume" {
      query.push_str(" ORDER BY s.total_volume DESC NULLS LAST");
    } else if sort_by == "least_volume" {
      query.push_str(" ORDER BY s.total_volume ASC");
    } else if sort_by == "biggest_file_size" {
      query.push_str(" ORDER BY s.total_inscription_size DESC NULLS LAST");
    } else if sort_by == "smallest_file_size" {
      query.push_str(" ORDER BY s.total_inscription_size ASC");
    } else if sort_by == "biggest_creation_fee" {
      query.push_str(" ORDER BY s.total_inscription_fees DESC NULLS LAST");
    } else if sort_by == "smallest_creation_fee" {
      query.push_str(" ORDER BY s.total_inscription_fees ASC");
    } else if sort_by == "earliest_first_inscribed_date" {
      query.push_str(" ORDER BY s.first_inscribed_date ASC");
    } else if sort_by == "latest_first_inscribed_date" {
      query.push_str(" ORDER BY s.first_inscribed_date DESC NULLS LAST");
    } else if sort_by == "earliest_last_inscribed_date" {
      query.push_str(" ORDER BY s.last_inscribed_date ASC");
    } else if sort_by == "latest_last_inscribed_date" {
      query.push_str(" ORDER BY s.last_inscribed_date DESC NULLS LAST");
    } else if sort_by == "biggest_supply" {
      query.push_str(" ORDER BY s.supply DESC NULLS LAST");
    } else if sort_by == "smallest_supply" {
      query.push_str(" ORDER BY s.supply ASC");
    }
    if page_size > 0 {
      query.push_str(format!(" LIMIT {}", page_size).as_str());
    }
    if page_number > 0 {
      query.push_str(format!(" OFFSET {}", page_number * page_size).as_str());
    }
    println!("Query: {}", query);
    let result = conn.query(
      query.as_str(), 
      &[]
    ).await?;
    let mut collections = Vec::new();
    for row in result {
      let collection = CollectionSummary {
        collection_symbol: row.get("collection_symbol"),
        name: row.get("name"),
        description: row.get("description"),
        twitter: row.get("twitter"),
        discord: row.get("discord"),
        website: row.get("website"),
        total_inscription_fees: row.get("total_inscription_fees"),
        total_inscription_size: row.get("total_inscription_size"),
        first_inscribed_date: row.get("first_inscribed_date"),
        last_inscribed_date: row.get("last_inscribed_date"),
        supply: row.get("supply"),
        range_start: row.get("range_start"),
        range_end: row.get("range_end"),
        total_volume: row.get("total_volume"),
        total_fees: row.get("total_fees"),
        total_on_chain_footprint: row.get("total_on_chain_footprint")
      };
      collections.push(collection);
    }
    Ok(collections)
  }

  async fn get_inscriptions_in_collection(pool: deadpool, collection_symbol: String, params: ParsedInscriptionQueryParams) -> anyhow::Result<Vec<MetadataWithCollectionMetadata>> {
    let conn = pool.get().await?;
    //1. build query
    let mut query = "with m as MATERIALIZED (SELECT o.*, c.collection_symbol, c.off_chain_metadata from ordinals o left join collections c on o.number=c.number where c.collection_symbol=$1".to_string();
    if params.content_types.len() > 0 {
      query.push_str(" AND (");
      for (i, content_type) in params.content_types.iter().enumerate() {
        if content_type == "text" {
          query.push_str("o.content_category = 'text'");
        } else if content_type == "image" {
          query.push_str("o.content_category = 'image'");
        } else if content_type == "gif" {
          query.push_str("o.content_category = 'gif'");
        } else if content_type == "audio" {
          query.push_str("o.content_category = 'audio'");
        } else if content_type == "video" {
          query.push_str("o.content_category = 'video'");
        } else if content_type == "html" {
          query.push_str("o.content_category = 'html'");
        } else if content_type == "json" {
          query.push_str("o.content_category = 'json'");
        } else if content_type == "namespace" {
          query.push_str("o.content_category = 'namespace'");
        } else if content_type == "javascript" {
          query.push_str("o.content_category = 'javascript'");
        }
        if i < params.content_types.len() - 1 {
          query.push_str(" OR ");
        }
      }
      query.push_str(")");
    }
    if params.satributes.len() > 0 {
      query.push_str(format!(" AND (o.satributes && array['{}'::varchar])", params.satributes.join("'::varchar,'")).as_str());
    }
    if params.charms.len() > 0 {
      query.push_str(format!(" AND (o.charms && array['{}'::varchar])", params.charms.join("'::varchar,'")).as_str());
    }
    if params.sort_by == "newest" {
      query.push_str(" ORDER BY o.sequence_number DESC");
    } else if params.sort_by == "oldest" {
      query.push_str(" ORDER BY o.sequence_number ASC");
    } else if params.sort_by == "newest_sat" {
      query.push_str(" ORDER BY o.sat DESC");
    } else if params.sort_by == "oldest_sat" {
      query.push_str(" ORDER BY o.sat ASC");
    } else if params.sort_by == "rarest_sat" {
      //query.push_str(" ORDER BY o.sat ASC");
    } else if params.sort_by == "commonest_sat" {
      //query.push_str(" ORDER BY o.sat DESC");
    } else if params.sort_by == "biggest" {
      query.push_str(" ORDER BY o.content_length DESC");
    } else if params.sort_by == "smallest" {
      query.push_str(" ORDER BY o.content_length ASC");
    } else if params.sort_by == "highest_fee" {
      query.push_str(" ORDER BY o.genesis_fee DESC");
    } else if params.sort_by == "lowest_fee" {
      query.push_str(" ORDER BY o.genesis_fee ASC");
    }
    query.push_str(") SELECT * from m");
    if params.page_size > 0 {
      query.push_str(format!(" LIMIT {}", params.page_size).as_str());
    }
    if params.page_number > 0 {
      query.push_str(format!(" OFFSET {}", params.page_number * params.page_size).as_str());
    }
    println!("Query: {}", query);
    let result = conn.query(
      query.as_str(), 
      &[&collection_symbol]
    ).await?;
    let mut inscriptions = Vec::new();
    for row in result {
      let inscription = MetadataWithCollectionMetadata {
        id: row.get("id"),
        content_length: row.get("content_length"),
        content_type: row.get("content_type"), 
        content_encoding: row.get("content_encoding"),
        content_category: row.get("content_category"),
        genesis_fee: row.get("genesis_fee"),
        genesis_height: row.get("genesis_height"),
        genesis_transaction: row.get("genesis_transaction"),
        pointer: row.get("pointer"),
        number: row.get("number"),
        sequence_number: row.get("sequence_number"),
        parents: row.get("parents"),
        delegate: row.get("delegate"),
        metaprotocol: row.get("metaprotocol"),
        on_chain_metadata: row.get("on_chain_metadata"),
        sat: row.get("sat"),
        sat_block: row.get("sat_block"),
        satributes: row.get("satributes"),
        charms: row.get("charms"),
        timestamp: row.get("timestamp"),
        sha256: row.get("sha256"),
        text: row.get("text"),
        referenced_ids: row.get("referenced_ids"),
        is_json: row.get("is_json"),
        is_maybe_json: row.get("is_maybe_json"),
        is_bitmap_style: row.get("is_bitmap_style"),
        is_recursive: row.get("is_recursive"),
        collection_symbol: row.get("collection_symbol"),
        off_chain_metadata: row.get("off_chain_metadata")
      };
      inscriptions.push(inscription);
    }
    Ok(inscriptions)
  }

  async fn get_inscription_collection_data(pool: deadpool, inscription_id: String) -> anyhow::Result<Vec<InscriptionCollectionData>> {
    let conn = pool.get().await?;
    let result = conn.query(
      "select c.id, c.number, c.off_chain_metadata, l.* from collections c left join collection_list l on c.collection_symbol=l.collection_symbol where c.id=$1", 
      &[&inscription_id]
    ).await?;
    let mut collection_data = Vec::new();
    for row in result {
      collection_data.push(InscriptionCollectionData {
        id: row.get("id"),
        number: row.get("number"),
        off_chain_metadata: row.get("off_chain_metadata"),
        collection_symbol: row.get("collection_symbol"),
        name: row.get("name"),
        image_uri: row.get("image_uri"),
        inscription_icon: row.get("inscription_icon"),
        description: row.get("description"),
        supply: row.get("supply"),
        twitter: row.get("twitter"),
        discord: row.get("discord"),
        website: row.get("website"),
        min_inscription_number: row.get("min_inscription_number"),
        max_inscription_number: row.get("max_inscription_number"),
        date_created: row.get("date_created")
      });
    }
    Ok(collection_data)
  }

  async fn get_inscription_collection_data_number(pool: deadpool, number: i64) -> anyhow::Result<Vec<InscriptionCollectionData>> {
    let conn = pool.get().await?;
    let result = conn.query(
      "select c.id, c.number, c.off_chain_metadata, l.* from collections c left join collection_list l on c.collection_symbol=l.collection_symbol where c.number=$1", 
      &[&number]
    ).await?;
    let mut collection_data = Vec::new();
    for row in result {
      collection_data.push(InscriptionCollectionData {
        id: row.get("id"),
        number: row.get("number"),
        off_chain_metadata: row.get("off_chain_metadata"),
        collection_symbol: row.get("collection_symbol"),
        name: row.get("name"),
        image_uri: row.get("image_uri"),
        inscription_icon: row.get("inscription_icon"),
        description: row.get("description"),
        supply: row.get("supply"),
        twitter: row.get("twitter"),
        discord: row.get("discord"),
        website: row.get("website"),
        min_inscription_number: row.get("min_inscription_number"),
        max_inscription_number: row.get("max_inscription_number"),
        date_created: row.get("date_created")
      });
    }
    Ok(collection_data)
  }

  async fn get_block_statistics(pool: deadpool, block: i64) -> anyhow::Result<CombinedBlockStats> {
    let conn = pool.get().await?;
    let result = conn.query_one(
      r"select b.*, 
        i.block_inscription_count, 
        i.block_inscription_size, 
        i.block_inscription_fees, 
        i.block_transfer_count, 
        i.block_transfer_size, 
        i.block_transfer_fees, 
        i.block_volume 
        from blockstats b 
        left join inscription_blockstats i on b.block_number=i.block_number 
        where b.block_number=$1",
      &[&block]
    ).await?;
    let block_stats = CombinedBlockStats {
      block_number: result.get("block_number"),
      block_timestamp: result.get("block_timestamp"),
      block_tx_count: result.get("block_tx_count"),
      block_size: result.get("block_size"),
      block_fees: result.get("block_fees"),
      min_fee: result.get("min_fee"),
      max_fee: result.get("max_fee"),
      average_fee: result.get("average_fee"),
      block_inscription_count: result.get("block_inscription_count"),
      block_inscription_size: result.get("block_inscription_size"),
      block_inscription_fees: result.get("block_inscription_fees"),
      block_transfer_count: result.get("block_transfer_count"),
      block_transfer_size: result.get("block_transfer_size"),
      block_transfer_fees: result.get("block_transfer_fees"),
      block_volume: result.get("block_volume")
    };
    Ok(block_stats)
  }

  async fn get_sat_block_statistics(pool: deadpool, block: i64) -> anyhow::Result<SatBlockStats> {
    let conn = pool.get().await?;
    let result = conn.query_one(r"
      select 
        s.*, 
        b.block_timestamp as sat_block_timestamp 
      from (
        SELECT 
          CAST($1 as BIGINT) as sat_block_number,
          CAST(count(*) AS BIGINT) as sat_block_inscription_count, 
          CAST(sum(content_length) AS BIGINT) as sat_block_inscription_size, 
          CAST(sum(genesis_fee) AS BIGINT) as sat_block_inscription_fees
        from ordinals where sat in (select sat from sat where block=$1)
      ) s 
      left join blockstats b on s.sat_block_number = b.block_number",
      &[&block]
    ).await?;
    let sat_block_stats = SatBlockStats {
      sat_block_number: result.get("sat_block_number"),
      sat_block_timestamp: result.get("sat_block_timestamp"),
      sat_block_inscription_count: result.get("sat_block_inscription_count"),
      sat_block_inscription_size: result.get("sat_block_inscription_size"),
      sat_block_inscription_fees: result.get("sat_block_inscription_fees")
    };
    Ok(sat_block_stats)
  }

  async fn get_blocks(pool: deadpool, params: CollectionQueryParams) -> anyhow::Result<Vec<CombinedBlockStats>> {
    let conn = pool.get().await?;
    let sort_by = params.sort_by.unwrap_or("newest".to_string());
    let page_size = std::cmp::min(params.page_size.unwrap_or(20), 100);
    let page_number = params.page_number.unwrap_or(0);
    //1. build query
    let mut query = r"
      select b.*, 
      i.block_inscription_count, 
      i.block_inscription_size, 
      i.block_inscription_fees, 
      i.block_transfer_count, 
      i.block_transfer_size, 
      i.block_transfer_fees, 
      i.block_volume from blockstats b 
      left join inscription_blockstats i 
      on b.block_number=i.block_number".to_string();
    if sort_by == "newest" {
      query.push_str(" ORDER BY b.block_number DESC");
    } else if sort_by == "oldest" {
      query.push_str(" ORDER BY b.block_number ASC");
    } else if sort_by == "most_txs" {
      query.push_str(" ORDER BY b.block_tx_count DESC");
    } else if sort_by == "least_txs" {
      query.push_str(" ORDER BY b.block_tx_count ASC");
    } else if sort_by == "most_inscriptions" {
      query.push_str(" ORDER BY i.block_inscription_count DESC NULLS LAST");
    } else if sort_by == "least_inscriptions" {
      query.push_str(" WHERE i.block_inscription_count > 0 ORDER BY i.block_inscription_count ASC");
    } else if sort_by == "biggest_block" {
      query.push_str(" ORDER BY b.block_size DESC");
    } else if sort_by == "smallest_block" {
      query.push_str(" ORDER BY b.block_size ASC");
    } else if sort_by == "biggest_total_inscriptions_size" {
      query.push_str(" ORDER BY i.block_inscription_size DESC NULLS LAST");
    } else if sort_by == "smallest_total_inscriptions_size" {
      query.push_str(" WHERE i.block_inscription_size > 0 ORDER BY i.block_inscription_size ASC");
    } else if sort_by == "highest_total_fees" {
      query.push_str(" ORDER BY b.block_fees DESC");
    } else if sort_by == "lowest_total_fees" {
      query.push_str(" ORDER BY b.block_fees ASC");
    } else if sort_by == "highest_inscription_fees" {
      query.push_str(" ORDER BY i.block_inscription_fees DESC NULLS LAST");
    } else if sort_by == "lowest_inscription_fees" {
      query.push_str(" WHERE i.block_inscription_fees > 0 ORDER BY i.block_inscription_fees ASC");
    } else if sort_by == "most_volume" {
      query.push_str(" ORDER BY i.block_volume DESC NULLS LAST");
    } else if sort_by == "least_volume" {
      query.push_str(" WHERE i.block_volume > 0 ORDER BY i.block_volume ASC");
    }

    if page_size > 0 {
      query.push_str(format!(" LIMIT {}", page_size).as_str());
    }
    if page_number > 0 {
      query.push_str(format!(" OFFSET {}", page_number * page_size).as_str());
    }
    println!("Query: {}", query);
    let result = conn.query(
      query.as_str(), 
      &[]
    ).await?;
    let mut blocks = Vec::new();
    for row in result {
      let block = CombinedBlockStats {
        block_number: row.get("block_number"),
        block_timestamp: row.get("block_timestamp"),
        block_tx_count: row.get("block_tx_count"),
        block_size: row.get("block_size"),
        block_fees: row.get("block_fees"),
        min_fee: row.get("min_fee"),
        max_fee: row.get("max_fee"),
        average_fee: row.get("average_fee"),
        block_inscription_count: row.get("block_inscription_count"),
        block_inscription_size: row.get("block_inscription_size"),
        block_inscription_fees: row.get("block_inscription_fees"),
        block_transfer_count: row.get("block_transfer_count"),
        block_transfer_size: row.get("block_transfer_size"),
        block_transfer_fees: row.get("block_transfer_fees"),
        block_volume: row.get("block_volume")
      };
      blocks.push(block);
    }
    Ok(blocks)
  }
  
  async fn get_collection_search_result(pool: deadpool, search_query: String) -> anyhow::Result<Vec<CollectionSummary>> {
    let conn = pool.get().await?;
    let escaped_search_query = format!("%{}%", search_query);
    let query = format!(r"
      select 
        l.collection_symbol, l.name, l.description, l.twitter, l.discord, l.website,
        s.total_inscription_fees,
        s.total_inscription_size,
        s.first_inscribed_date,
        s.last_inscribed_date,
        s.supply,
        s.range_start,
        s.range_end,
        s.total_volume,
        s.total_fees,
        s.total_on_chain_footprint
      from collection_list l 
      left join collection_summary s 
      on l.collection_symbol=s.collection_symbol 
      where l.name ILIKE $1 or l.description ILIKE $1 
      order by s.total_volume desc nulls last
      limit 5");
    let result = conn.query(query.as_str(), &[&escaped_search_query]).await?;
    let mut collections = Vec::new();
    for row in result {
      let collection = CollectionSummary {
        collection_symbol: row.get("collection_symbol"),
        name: row.get("name"),
        description: row.get("description"),
        twitter: row.get("twitter"),
        discord: row.get("discord"),
        website: row.get("website"),
        total_inscription_fees: row.get("total_inscription_fees"),
        total_inscription_size: row.get("total_inscription_size"),
        first_inscribed_date: row.get("first_inscribed_date"),
        last_inscribed_date: row.get("last_inscribed_date"),
        supply: row.get("supply"),
        range_start: row.get("range_start"),
        range_end: row.get("range_end"),
        total_volume: row.get("total_volume"),
        total_fees: row.get("total_fees"),
        total_on_chain_footprint: row.get("total_on_chain_footprint")
      };
      collections.push(collection);
    }
    Ok(collections)
  }

  async fn get_search_result(pool: deadpool, search_query: String) -> anyhow::Result<SearchResult> {
    let id: Regex = Regex::new(r"^[[:xdigit:]]{64}i\d+$").unwrap();
    let address: Regex = Regex::new(r"^(bc1p[a-zA-Z0-9]{58}|bc1q[a-zA-Z0-9]{38}|[13][a-zA-HJ-NP-Z0-9]{25,34})$").unwrap();
    let number: Regex = Regex::new(r"^-?\d+$").unwrap();

    let search_query = search_query.trim();
    let mut search_result = SearchResult {
      collections: Vec::new(),
      inscription: None,      
      address: None,
      block: None,
      sat: None,
    };
    if number.is_match(search_query) {
      let number = search_query.parse::<i64>().unwrap();
      let potential_inscription = Self::get_ordinal_metadata_by_number(pool.clone(), number).await;
      let potential_block = Self::get_block_statistics(pool.clone(), number).await;
      let potential_sat = Self::get_sat_metadata(pool, number).await;
      search_result.inscription = potential_inscription.ok();
      search_result.block = potential_block.ok();
      search_result.sat = potential_sat.ok();
    } else {
      if id.is_match(search_query) {
        let potential_inscription = Self::get_ordinal_metadata(pool, search_query.to_string()).await;
        search_result.inscription = potential_inscription.ok();
      } else if address.is_match(search_query) {
        search_result.address = Some(search_query.to_string());
      } else {
        let potential_collections = Self::get_collection_search_result(pool, search_query.to_string()).await;
        search_result.collections = potential_collections?;
      }
    }
    Ok(search_result)
  }

  async fn create_metadata_insert_trigger(pool: deadpool_postgres::Pool<>) -> anyhow::Result<()> {
    let conn = pool.get().await?;
    conn.simple_query(r"CREATE OR REPLACE FUNCTION before_metadata_insert() RETURNS TRIGGER AS $$
      DECLARE previous_delegate_total INTEGER;
      DECLARE ref_id VARCHAR(80);
      DECLARE previous_reference_total INTEGER;
      DECLARE inscription_satribute VARCHAR(30);
      DECLARE previous_satribute_total INTEGER;
      BEGIN
        -- RAISE NOTICE 'insert_metadata: waiting for lock';
        LOCK TABLE ordinals IN EXCLUSIVE MODE;
        -- RAISE NOTICE 'insert_metadata: lock acquired';

        -- 1. Update delegates
        IF NEW.delegate IS NOT NULL THEN
          -- Get the previous total for the same delegate id
          SELECT total INTO previous_delegate_total FROM delegates_total WHERE delegate_id = NEW.delegate;
          -- Insert or update the total in delegates_total
          INSERT INTO delegates_total (delegate_id, total) VALUES (NEW.delegate, COALESCE(previous_delegate_total, 0) + 1)
          ON CONFLICT (delegate_id) DO UPDATE SET total = EXCLUDED.total;
          -- Insert the new delegate
          INSERT INTO delegates (delegate_id, bootleg_id, bootleg_number, bootleg_sequence_number, bootleg_edition) VALUES (NEW.delegate, NEW.id, NEW.number, NEW.sequence_number, COALESCE(previous_delegate_total, 0) + 1)
          ON CONFLICT DO NOTHING;
        END IF;

        -- 2. Update references
        FOREACH ref_id IN ARRAY NEW.referenced_ids
        LOOP
          -- Get the previous total for the same reference id
          SELECT total INTO previous_reference_total FROM inscription_references_total WHERE reference_id = ref_id;
          -- Insert or update the total in inscription_references_total
          INSERT INTO inscription_references_total (reference_id, total) VALUES (ref_id, COALESCE(previous_reference_total, 0) + 1)
          ON CONFLICT (reference_id) DO UPDATE SET total = EXCLUDED.total;
          -- Insert the new reference
          INSERT INTO inscription_references (reference_id, recursive_id, recursive_number, recursive_sequence_number, recursive_edition) VALUES (ref_id, NEW.id, NEW.number, NEW.sequence_number, COALESCE(previous_reference_total, 0) + 1)
          ON CONFLICT DO NOTHING;
        END LOOP;

        -- 3. Update satributes
        FOREACH inscription_satribute IN ARRAY NEW.satributes
        LOOP
          -- Get the previous total for the same satribute
          SELECT total INTO previous_satribute_total FROM inscription_satributes_total WHERE satribute = inscription_satribute;
          -- Insert or update the total in inscription_satributes_total
          INSERT INTO inscription_satributes_total (satribute, total) VALUES (inscription_satribute, COALESCE(previous_satribute_total, 0) + 1)
          ON CONFLICT (satribute) DO UPDATE SET total = EXCLUDED.total;
          -- Insert the new satribute
          INSERT INTO inscription_satributes (satribute, sat, inscription_id, inscription_number, inscription_sequence_number, satribute_edition) VALUES (inscription_satribute, NEW.sat, NEW.id, NEW.number, NEW.sequence_number, COALESCE(previous_satribute_total, 0) + 1)
          ON CONFLICT DO NOTHING;
        END LOOP;

        RETURN NEW;
      END;
      $$ LANGUAGE plpgsql;").await?;
    conn.simple_query(
      r#"CREATE OR REPLACE TRIGGER before_metadata_insert
      BEFORE INSERT ON ordinals
      FOR EACH ROW
      EXECUTE PROCEDURE before_metadata_insert();"#).await?;
    Ok(())
  }

  async fn create_transfer_insert_trigger(pool: deadpool_postgres::Pool<>) -> anyhow::Result<()> {
    let conn = pool.get().await?;
    conn.simple_query(r"CREATE OR REPLACE FUNCTION before_transfer_insert() RETURNS TRIGGER AS $$
      DECLARE v_collection_symbol TEXT;
      BEGIN
        -- RAISE NOTICE 'insert_transfers: waiting for lock';
        LOCK TABLE transfers IN EXCLUSIVE MODE;
        -- RAISE NOTICE 'insert_transfers: lock acquired';
        SELECT collection_symbol INTO v_collection_symbol FROM collections WHERE id = NEW.id;
        IF EXISTS (SELECT 1 FROM collections WHERE id = NEW.id) THEN
          UPDATE collection_summary
          SET total_volume = coalesce(total_volume, 0) + new.price,
              total_fees = coalesce(total_fees, 0) + NEW.tx_fee,
              total_on_chain_footprint = coalesce(total_on_chain_footprint, 0) + NEW.tx_size
            WHERE collection_symbol = v_collection_symbol;
        END IF;
        RETURN NEW;
      END;
      $$ LANGUAGE plpgsql;").await?;
    conn.simple_query(
      r#"CREATE OR REPLACE TRIGGER before_transfer_insert
      BEFORE INSERT ON transfers
      FOR EACH ROW
      EXECUTE PROCEDURE before_transfer_insert();"#).await?;
    Ok(())
  }

  async fn create_edition_insert_trigger(pool: deadpool_postgres::Pool<>) -> anyhow::Result<()> {
    let conn = pool.get().await?;
    conn.simple_query(r#"
      CREATE OR REPLACE FUNCTION before_edition_insert() RETURNS TRIGGER AS $$
      DECLARE previous_total INTEGER;
      DECLARE new_total INTEGER;
      BEGIN
        -- Get the previous total for the same sha256, or default to 0
        SELECT total INTO previous_total FROM editions_total WHERE sha256 = NEW.sha256;
        new_total := COALESCE(previous_total, 0) + 1;
        -- RAISE NOTICE 'previous_total: %, new_total: %', previous_total, new_total;
        -- Set the edition number in the new row to previous + 1
        NEW.edition := new_total;
      
        -- Insert or update the total in editions_total
        INSERT INTO editions_total (sha256, total) VALUES (NEW.sha256, new_total)
        ON CONFLICT (sha256) DO UPDATE SET total = EXCLUDED.total;
      
        RETURN NEW;
      END;
      $$ LANGUAGE plpgsql;"#).await?;
    conn.simple_query(
      r#"CREATE OR REPLACE TRIGGER before_edition_insert
      BEFORE INSERT ON editions
      FOR EACH ROW
      EXECUTE PROCEDURE before_edition_insert();"#).await?;
    Ok(())
  }

  async fn create_edition_procedure(pool: deadpool_postgres::Pool<>) -> anyhow::Result<()> {
    let conn = pool.get().await?;
    conn.simple_query(r"DROP PROCEDURE IF EXISTS update_editions").await?;
    conn.simple_query(
      r#"CREATE PROCEDURE update_editions()
      LANGUAGE plpgsql
      AS $$
      BEGIN
      LOCK TABLE ordinals IN EXCLUSIVE MODE;
      RAISE NOTICE 'update_editions: lock acquired';
      IF NOT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'editions') THEN
      INSERT into proc_log(proc_name, step_name, ts) values ('EDITIONS', 'START_CREATE', now());
      CREATE TABLE editions as select id, number, sequence_number, sha256, row_number() OVER(PARTITION BY sha256 ORDER BY sequence_number asc) as edition from ordinals;
      INSERT into proc_log(proc_name, step_name, ts, rows_returned) values ('EDITIONS', 'FINISH_CREATE', now(), NULL);
      INSERT into proc_log(proc_name, step_name, ts) values ('EDITIONS', 'START_CREATE_TOTAL', now());
      CREATE TABLE editions_total as select sha256, count(*) as total from ordinals where sha256 is not null group by sha256;
      INSERT into proc_log(proc_name, step_name, ts, rows_returned) values ('EDITIONS', 'FINISH_CREATE_TOTAL', now(), NULL);
      ALTER TABLE editions add primary key (id);
      CREATE INDEX IF NOT EXISTS idx_number ON editions (number);
      CREATE INDEX IF NOT EXISTS idx_sha256 ON editions (sha256);
      ALTER TABLE editions_total add primary key (sha256);
      INSERT into proc_log(proc_name, step_name, ts, rows_returned) values ('EDITIONS', 'FINISH_INDEX', now(), NULL);
      ELSE
      DROP TABLE IF EXISTS editions_new, editions_total_new;
      INSERT into proc_log(proc_name, step_name, ts) values ('EDITIONS', 'START_CREATE_NEW', now());
      CREATE TABLE editions_new as select id, number, sequence_number, sha256, row_number() OVER(PARTITION BY sha256 ORDER BY sequence_number asc) as edition from ordinals;
      INSERT into proc_log(proc_name, step_name, ts, rows_returned) values ('EDITIONS', 'FINISH_CREATE_NEW', now(), NULL);
      INSERT into proc_log(proc_name, step_name, ts) values ('EDITIONS', 'START_CREATE_TOTAL_NEW', now());
      CREATE TABLE editions_total_new as select sha256, count(*) as total from ordinals where sha256 is not null group by sha256;
      INSERT into proc_log(proc_name, step_name, ts, rows_returned) values ('EDITIONS', 'FINISH_CREATE_TOTAL_NEW', now(), NULL);
      ALTER TABLE editions_new add primary key (id);
      CREATE INDEX IF NOT EXISTS idx_number ON editions_new (number);
      CREATE INDEX IF NOT EXISTS idx_sha256 ON editions_new (sha256);
      ALTER TABLE editions_total_new add primary key (sha256);
      ALTER TABLE editions RENAME to editions_old; 
      ALTER TABLE editions_new RENAME to editions;
      ALTER TABLE editions_total RENAME to editions_total_old;
      ALTER TABLE editions_total_new RENAME to editions_total;
      DROP TABLE IF EXISTS editions_old;
      DROP TABLE IF EXISTS editions_total_old;
      INSERT into proc_log(proc_name, step_name, ts, rows_returned) values ('EDITIONS', 'FINISH_INDEX_NEW', now(), NULL);
      END IF;
      END;
      $$;"#).await?;
    Ok(())
  }
  
  async fn create_weights_procedure(pool: deadpool_postgres::Pool<>) -> anyhow::Result<()> {
    let conn = pool.get().await?;
    conn.simple_query(r"DROP PROCEDURE IF EXISTS update_weights").await?;
    conn.simple_query(
      r#"CREATE OR REPLACE PROCEDURE update_weights()
      LANGUAGE plpgsql
      AS $$
      BEGIN
      DROP TABLE IF EXISTS weights_1;
      DROP TABLE IF EXISTS weights_2;
      DROP TABLE IF EXISTS weights_3;
      DROP TABLE IF EXISTS weights_4;
      DROP TABLE IF EXISTS weights_5;
      IF NOT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'weights') THEN
      INSERT into proc_log(proc_name, step_name, ts) values ('WEIGHTS', 'START_CREATE_1', now());
        CREATE TABLE weights_1 as
        select sha256, 
               min(sequence_number) as first_number, 
               sum(genesis_fee) as total_fee, 
               max(content_length) as content_length, 
               count(*) as count
        from ordinals 
        where content_type ILIKE 'image%' and content_type !='image/svg+xml' and sha256 in (
          select sha256 
          from content_moderation 
          where coalesce(human_override_moderation_flag, automated_moderation_flag) = 'SAFE_MANUAL' 
          or coalesce(human_override_moderation_flag, automated_moderation_flag) = 'SAFE_AUTOMATED')
        group by sha256;
      INSERT into proc_log(proc_name, step_name, ts, rows_returned) values ('WEIGHTS', 'FINISH_CREATE_1', now(), NULL);
      INSERT into proc_log(proc_name, step_name, ts) values ('WEIGHTS', 'START_CREATE_2', now());
        CREATE TABLE weights_2 AS
        SELECT w.*,
              CASE
                  WHEN db.dbscan_class IS NULL THEN -w.first_number
                  WHEN db.dbscan_class = -1 THEN -w.first_number
                  ELSE db.dbscan_class
              END AS CLASS
        FROM weights_1 w
        LEFT JOIN dbscan db ON w.sha256=db.sha256;
      INSERT into proc_log(proc_name, step_name, ts, rows_returned) values ('WEIGHTS', 'FINISH_CREATE_2', now(), NULL);
      INSERT into proc_log(proc_name, step_name, ts) values ('WEIGHTS', 'START_CREATE_3', now());
        CREATE TABLE weights_3 AS
        SELECT sha256, 
              min(class) as class,
              min(first_number) AS first_number,
              sum(total_fee) AS total_fee
        FROM weights_2
        GROUP BY sha256;
      INSERT into proc_log(proc_name, step_name, ts, rows_returned) values ('WEIGHTS', 'FINISH_CREATE_3', now(), NULL);
      INSERT into proc_log(proc_name, step_name, ts) values ('WEIGHTS', 'START_CREATE_4', now());
        CREATE TABLE weights_4 AS
        SELECT *,
              (10-log(10,first_number+1))*total_fee AS weight
        FROM weights_3;
      INSERT into proc_log(proc_name, step_name, ts, rows_returned) values ('WEIGHTS', 'FINISH_CREATE_4', now(), NULL);
      INSERT into proc_log(proc_name, step_name, ts) values ('WEIGHTS', 'START_CREATE_5', now());
        CREATE TABLE weights_5 AS
        SELECT *,
              sum(weight) OVER(ORDER BY class, first_number)/sum(weight) OVER() AS band_end, 
              coalesce(sum(weight) OVER(ORDER BY class, first_number ROWS BETWEEN UNBOUNDED PRECEDING AND 1 PRECEDING),0)/sum(weight) OVER() AS band_start
        FROM weights_4;
      INSERT into proc_log(proc_name, step_name, ts, rows_returned) values ('WEIGHTS', 'FINISH_CREATE_5', now(), NULL);
      INSERT into proc_log(proc_name, step_name, ts) values ('WEIGHTS', 'START_CREATE_6', now());
      CREATE TABLE weights AS
      SELECT sha256,
            class,
            first_number,
            CAST(total_fee AS FLOAT8),
            CAST(weight AS FLOAT8),
            CAST(band_start AS FLOAT8),
            CAST(band_end AS FLOAT8),
            CAST(min(band_start) OVER(PARTITION BY class) AS FLOAT8) AS class_band_start,
            CAST(max(band_end) OVER(PARTITION BY class) AS FLOAT8) AS class_band_end
      FROM weights_5;
      INSERT into proc_log(proc_name, step_name, ts, rows_returned) values ('WEIGHTS', 'FINISH_CREATE_6', now(), NULL);
        CREATE INDEX idx_band_start ON weights (band_start);
        CREATE INDEX idx_band_end ON weights (band_end);
        ALTER TABLE weights owner to vermilion_user;
      INSERT into proc_log(proc_name, step_name, ts, rows_returned) values ('WEIGHTS', 'FINISH_INDEX', now(), NULL);
      
      ELSE
      
      INSERT into proc_log(proc_name, step_name, ts) values ('WEIGHTS', 'START_CREATE_NEW', now());
      DROP TABLE IF EXISTS weights_new;
        CREATE TABLE weights_1 as
        select sha256, 
               min(sequence_number) as first_number, 
               sum(genesis_fee) as total_fee, 
               max(content_length) as content_length, 
               count(*) as count
        from ordinals 
        where content_type ILIKE 'image%' and content_type !='image/svg+xml' and sha256 in (
          select sha256 
          from content_moderation 
          where coalesce(human_override_moderation_flag, automated_moderation_flag) = 'SAFE_MANUAL' 
          or coalesce(human_override_moderation_flag, automated_moderation_flag) = 'SAFE_AUTOMATED')
        group by sha256;
      INSERT into proc_log(proc_name, step_name, ts, rows_returned) values ('WEIGHTS', 'FINISH_CREATE_NEW_1', now(), NULL);
      INSERT into proc_log(proc_name, step_name, ts) values ('WEIGHTS', 'START_CREATE_NEW_2', now());
        CREATE TABLE weights_2 AS
        SELECT w.*,
              CASE
                  WHEN db.dbscan_class IS NULL THEN -w.first_number
                  WHEN db.dbscan_class = -1 THEN -w.first_number
                  ELSE db.dbscan_class
              END AS CLASS
        FROM weights_1 w
        LEFT JOIN dbscan db ON w.sha256=db.sha256;
      INSERT into proc_log(proc_name, step_name, ts, rows_returned) values ('WEIGHTS', 'FINISH_CREATE_NEW_2', now(), NULL);
      INSERT into proc_log(proc_name, step_name, ts) values ('WEIGHTS', 'START_CREATE_NEW_3', now());
        CREATE TABLE weights_3 AS
        SELECT sha256, 
              min(class) as class,
              min(first_number) AS first_number,
              sum(total_fee) AS total_fee
        FROM weights_2
        GROUP BY sha256;
      INSERT into proc_log(proc_name, step_name, ts, rows_returned) values ('WEIGHTS', 'FINISH_CREATE_NEW_3', now(), NULL);
      INSERT into proc_log(proc_name, step_name, ts) values ('WEIGHTS', 'START_CREATE_NEW_4', now());
        CREATE TABLE weights_4 AS
        SELECT *,
              (10-log(10,first_number+1))*total_fee AS weight
        FROM weights_3;
      INSERT into proc_log(proc_name, step_name, ts, rows_returned) values ('WEIGHTS', 'FINISH_CREATE_NEW_4', now(), NULL);
      INSERT into proc_log(proc_name, step_name, ts) values ('WEIGHTS', 'START_CREATE_NEW_5', now());
        CREATE TABLE weights_5 AS
        SELECT *,
              sum(weight) OVER(ORDER BY class, first_number)/sum(weight) OVER() AS band_end, 
              coalesce(sum(weight) OVER(ORDER BY class, first_number ROWS BETWEEN UNBOUNDED PRECEDING AND 1 PRECEDING),0)/sum(weight) OVER() AS band_start
        FROM weights_4;
      INSERT into proc_log(proc_name, step_name, ts, rows_returned) values ('WEIGHTS', 'FINISH_CREATE_NEW_5', now(), NULL);
      INSERT into proc_log(proc_name, step_name, ts) values ('WEIGHTS', 'START_CREATE_NEW_6', now());
      CREATE TABLE weights_new AS
      SELECT sha256,
            class,
            first_number,
            CAST(total_fee AS FLOAT8),
            CAST(weight AS FLOAT8),
            CAST(band_start AS FLOAT8),
            CAST(band_end AS FLOAT8),
            CAST(min(band_start) OVER(PARTITION BY class) AS FLOAT8) AS class_band_start,
            CAST(max(band_end) OVER(PARTITION BY class) AS FLOAT8) AS class_band_end
      FROM weights_5;
      INSERT into proc_log(proc_name, step_name, ts, rows_returned) values ('WEIGHTS', 'FINISH_CREATE_NEW_6', now(), NULL);
        CREATE INDEX new_idx_band_start ON weights_new (band_start);
        CREATE INDEX new_idx_band_end ON weights_new (band_end);
        ALTER TABLE weights RENAME to weights_old;
        ALTER TABLE weights_new RENAME to weights;
        ALTER TABLE weights owner to vermilion_user;
        DROP TABLE IF EXISTS weights_old;
        ALTER INDEX new_idx_band_start RENAME TO idx_band_start;
        ALTER INDEX new_idx_band_end RENAME TO idx_band_end;
      INSERT into proc_log(proc_name, step_name, ts, rows_returned) values ('WEIGHTS', 'FINISH_INDEX_NEW', now(), NULL);
      END IF;      
      DROP TABLE IF EXISTS weights_1;
      DROP TABLE IF EXISTS weights_2;
      DROP TABLE IF EXISTS weights_3;
      DROP TABLE IF EXISTS weights_4;
      DROP TABLE IF EXISTS weights_5;
      END;
      $$;"#).await?;
    Ok(())
  }
  
  async fn create_collection_summary_procedure(pool: deadpool_postgres::Pool<>) -> anyhow::Result<()> {
    let conn = pool.get().await?;
    conn.simple_query(
      r#"
      CREATE OR REPLACE PROCEDURE update_collection_summary()
      LANGUAGE plpgsql
      AS $$
      BEGIN
      LOCK TABLE transfers IN EXCLUSIVE MODE;
      RAISE NOTICE 'update_collection_summary: lock acquired';
        with a as (
          select 
            c.collection_symbol,             
            count(*) as supply, 
            sum(o.content_length) as total_inscription_size,
            sum(o.genesis_fee) as total_inscription_fees,
            min(timestamp) as first_inscribed_date,
            max(timestamp) as last_inscribed_date,
            min(o.number) as range_start, 
            max(o.number) as range_end 
          from collections c 
          inner join ordinals o on c.id=o.id 
          group by c.collection_symbol
        ), b as (
          select 
            c.collection_symbol, 
            sum(price) as total_volume, 
            sum(tx_fee) as total_fees, 
            sum(tx_size) as total_on_chain_footprint 
            from collections c left join transfers t on c.id=t.id 
            group by c.collection_symbol
        ) 
        INSERT INTO collection_summary (collection_symbol, supply, total_inscription_size, total_inscription_fees, first_inscribed_date, last_inscribed_date, range_start, range_end, total_volume, total_fees, total_on_chain_footprint) 
        select 
          a.*, 
          b.total_volume, 
          b.total_fees, 
          b.total_on_chain_footprint 
        from a left join b on a.collection_symbol=b.collection_symbol
        ON CONFLICT (collection_symbol) DO UPDATE SET
        supply = EXCLUDED.supply,
        total_inscription_size = EXCLUDED.total_inscription_size,
        total_inscription_fees = EXCLUDED.total_inscription_fees,
        first_inscribed_date = EXCLUDED.first_inscribed_date,
        last_inscribed_date = EXCLUDED.last_inscribed_date,
        range_start = EXCLUDED.range_start,
        range_end = EXCLUDED.range_end,
        total_volume = EXCLUDED.total_volume,
        total_fees = EXCLUDED.total_fees,
        total_on_chain_footprint = EXCLUDED.total_on_chain_footprint;
      END;
      $$;"#).await?;
    Ok(())
  }
  
  async fn update_collection_summary(pool: deadpool_postgres::Pool<>) -> anyhow::Result<()> {
    let conn = pool.get().await?;
    conn.simple_query("CALL update_collection_summary()").await?;
    Ok(())
  }

  async fn create_procedure_log(pool: deadpool_postgres::Pool<>) -> anyhow::Result<()> {
    let conn = pool.get().await?;
    conn.simple_query(
      r"CREATE TABLE IF NOT EXISTS proc_log (
        id SERIAL PRIMARY KEY,
        proc_name varchar(40),
        step_name varchar(40),
        ts timestamp,
        rows_returned int
      )").await?;
    Ok(())
  }

  async fn create_ordinals_full_view(pool: deadpool_postgres::Pool<>) -> anyhow::Result<()> {
    let conn = pool.get().await?;
    conn.simple_query(
      r"CREATE OR REPLACE VIEW ordinals_full_v AS
        SELECT o.*, 
               c.collection_symbol, 
               c.off_chain_metadata, 
               l.name as collection_name 
        FROM ordinals o 
        left join collections c on o.id=c.id 
        left join collection_list l on c.collection_symbol=l.collection_symbol").await?;
    Ok(())
  }
  
}