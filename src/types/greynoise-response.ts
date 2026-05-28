/**
 * Represents a tag from GreyNoise that categorizes IP behavior
 */
export interface GreyNoiseTag {
  /** Unique identifier for the tag */
  id: string;
  /** Human-readable name of the tag */
  name: string;
  /** URL-friendly version of the tag name */
  slug: string;
  /** Detailed explanation of what this tag represents */
  description: string;
  /** The category this tag belongs to */
  category: string;
  /** The inferred intention behind the activity identified by this tag */
  intention: string;
  /** Display label for the tag */
  label: string;
  /** Whether GreyNoise recommends blocking IPs with this tag */
  recommend_block: boolean;
  /** List of CVE identifiers associated with this tag */
  cves: string[];
  /** ISO timestamp when this tag was created */
  created_at: string;
  /** List of URLs to reference materials about this tag */
  references: string[];
}

/**
 * Response structure from the GreyNoise tags endpoint
 */
export interface GreyNoiseTagsResponse {
  /** Array of tag objects */
  tags: GreyNoiseTag[];
}

/**
 * Represents aggregated statistics for tag activity
 */
export interface GreyNoiseTagActivityAggregations {
  /** Total number of IPs associated with this tag */
  total_ips: number;
  /** Counts of IPs by classification type */
  classification?: {
    /** Count of malicious IPs */
    malicious?: number;
    /** Count of suspicious IPs */
    suspicious?: number;
    /** Count of benign IPs */
    benign?: number;
    /** Count of unknown IPs */
    unknown?: number;
    /** Support for other classifications */
    [key: string]: number | undefined;
  };
}

/**
 * Represents activity data for a specific tag
 */
export interface GreyNoiseTagActivity {
  /** Statistical aggregations for the tag */
  aggregations?: GreyNoiseTagActivityAggregations;
  /** Time-series data for the tag activity */
  timeline?: Array<{
    /** Time bucket identifier (typically a date string) */
    bucket: string;
    /** Metrics for this time period */
    metrics: {
      /** Number of IPs active during this time period */
      total_ips: number;
    };
  }>;
}

/**
 * Simplified tag information with activity summary
 */
export interface ActivitySummaryTag {
  /** Human-readable name of the tag */
  name: string;
  /** URL-friendly version of the tag name */
  slug: string;
  /** Total number of IPs associated with this tag */
  total_ips: number;
  /** Counts of IPs by classification type */
  classification: Record<string, number>;
}

/**
 * Response structure for tag activity data
 */
export interface TagActivityResponse {
  /** URL-friendly version of the tag name */
  slug: string;
  /** Activity data broken down by classification */
  activity: {
    /** Activity data for malicious IPs */
    malicious?: Array<{
      /** Start time of the activity period */
      start: string;
      /** End time of the activity period */
      end: string;
      /** Whether to include the start time in the period */
      include_start: boolean;
      /** Whether to include the end time in the period */
      include_end: boolean;
      /** Timestamp for the activity */
      timestamp: string;
      /** Number of active IPs in this period */
      active_ips: number;
    }>;
    /** Activity data for suspicious IPs */
    suspicious?: Array<any>;
    /** Activity data for benign IPs */
    benign?: Array<any>;
    /** Activity data for unknown IPs */
    unknown?: Array<any>;
    /** Support for other classifications */
    [key: string]: Array<any> | undefined;
  };
  /** Statistical aggregations for the tag */
  aggregations: {
    /** Total number of IPs associated with this tag */
    total_ips: number;
    /** Counts of IPs by classification type */
    classification: {
      /** Count of malicious IPs */
      malicious?: number;
      /** Count of suspicious IPs */
      suspicious?: number;
      /** Count of benign IPs */
      benign?: number;
      /** Count of unknown IPs */
      unknown?: number;
      /** Support for other classifications */
      [key: string]: number | undefined;
    };
  };
  /** Metadata about the activity data */
  metadata: {
    /** Time granularity of the data (e.g., 'day', 'hour') */
    granularity: string;
    /** Start date for the data range */
    start_date: string;
    /** End date for the data range */
    end_date: string;
  };
}

/**
 * Response structure for GNQL (GreyNoise Query Language) statistics
 */
export interface GnqlStatsResponse {
  /** Total count of matching records */
  count: number;
  /** The original GNQL query string */
  query: string;
  /** The executed query if the original query was adjusted due to plan limitations */
  adjusted_query?: string;
  /** Statistical breakdowns of the query results */
  stats: {
    /** Breakdown by classification */
    classifications: Array<{
      /** Classification type (e.g., 'malicious', 'benign') */
      classification: string;
      /** Number of IPs with this classification */
      count: number;
    }>;
    /** Breakdown by spoofable status */
    spoofable?: Array<{
      /** Whether the IP is spoofable */
      spoofable: boolean;
      /** Number of IPs with this spoofable status */
      count: number;
    }>;
    /** Breakdown by organization */
    organizations: Array<{
      /** Organization name */
      organization: string;
      /** Number of IPs from this organization */
      count: number;
    }>;
    /** Breakdown by country */
    countries: Array<{
      /** Country name */
      country: string;
      /** Number of IPs from this country */
      count: number;
    }>;
    /** Breakdown by source country */
    source_countries?: Array<{
      /** Country name */
      country: string;
      /** Number of IPs from this source country */
      count: number;
    }>;
    /** Breakdown by destination country */
    destination_countries?: Array<{
      /** Country name */
      country: string;
      /** Number of IPs targeting this destination country */
      count: number;
    }>;
    /** Breakdown by tag */
    tags: Array<{
      /** Tag name */
      tag: string;
      /** Tag ID */
      id: string;
      /** Number of IPs with this tag */
      count: number;
    }>;
    /** Breakdown by actor */
    actors: Array<{
      /** Actor name */
      actor: string;
      /** Number of IPs associated with this actor */
      count: number;
    }>;
    /** Breakdown by operating system */
    operating_systems?: Array<{
      /** Operating system name */
      operating_system: string;
      /** Number of IPs running this OS */
      count: number;
    }> | null;
    /** Breakdown by category */
    categories?: Array<{
      /** Category name */
      category: string;
      /** Number of IPs in this category */
      count: number;
    }>;
    /** Breakdown by ASN (Autonomous System Number) */
    asns?: Array<{
      /** ASN identifier */
      asn: string;
      /** Number of IPs in this ASN */
      count: number;
    }>;
    /** Support for other statistical breakdowns */
    [key: string]: any;
  };
}

/**
 * Response structure for trending tags from GreyNoise
 */
export interface TrendingTagsResponse {
  /** Array of trending tag information */
  tags: Array<{
    /** Unique identifier for the tag */
    id: string;
    /** Display label for the tag */
    label: string;
    /** URL-friendly version of the tag name */
    slug: string;
    /** Human-readable name of the tag */
    name: string;
    /** The category this tag belongs to */
    category: string;
    /** The inferred intention behind the activity identified by this tag */
    intention: string;
    /** List of CVE identifiers associated with this tag */
    cves: string[];
    /** ISO timestamp when this tag was created */
    created_at: string;
    /** Total number of IPs associated with this tag */
    total_ips: number;
    /** Trending score value */
    score: number;
  }>;
}

/**
 * Response structure for CVE (Common Vulnerabilities and Exposures) details
 */
export interface CVEDetailsResponse {
  /** CVE identifier */
  id: string;
  /** Basic vulnerability information */
  details: {
    /** Human-readable name of the vulnerability */
    vulnerability_name: string;
    /** Detailed description of the vulnerability */
    vulnerability_description: string;
    /** CVSS (Common Vulnerability Scoring System) score */
    cve_cvss_score: number;
    /** Affected product name */
    product: string;
    /** Vendor of the affected product */
    vendor: string;
    /** Whether this CVE has been published to the NIST NVD */
    published_to_nist_nvd: boolean;
  };
  /** Timeline information for the vulnerability */
  timeline: {
    /** When the CVE was first published */
    cve_published_date: string;
    /** When the CVE was last updated */
    cve_last_updated_date: string;
    /** First known publication date */
    first_known_published_date: string;
    /** When the CVE was added to CISA KEV (Known Exploited Vulnerabilities) catalog, if applicable */
    cisa_kev_date_added?: string;
  };
  /** Details about exploitation of this vulnerability */
  exploitation_details: {
    /** The attack vector (e.g., 'network', 'local') */
    attack_vector: string;
    /** Whether exploits have been found in the wild */
    exploit_found: boolean;
    /** Whether this vulnerability is registered in the KEV catalog */
    exploitation_registered_in_kev: boolean;
    /** EPSS (Exploit Prediction Scoring System) score */
    epss_score: number;
  };
  /** Statistics about exploitation */
  exploitation_stats: {
    /** Number of known exploits available */
    number_of_available_exploits: number;
    /** Number of threat actors known to be exploiting this vulnerability */
    number_of_threat_actors_exploiting_vulnerability: number;
    /** Number of botnets known to be exploiting this vulnerability */
    number_of_botnets_exploiting_vulnerability: number;
  };
  /** Information about observed exploitation activity */
  exploitation_activity: {
    /** Whether exploitation activity has been observed */
    activity_seen: boolean;
    /** Number of benign IPs seen exploiting this vulnerability in the last 1 day */
    benign_ip_count_1d: number;
    /** Number of benign IPs seen exploiting this vulnerability in the last 10 days */
    benign_ip_count_10d: number;
    /** Number of benign IPs seen exploiting this vulnerability in the last 30 days */
    benign_ip_count_30d: number;
    /** Number of threat IPs seen exploiting this vulnerability in the last 1 day */
    threat_ip_count_1d: number;
    /** Number of threat IPs seen exploiting this vulnerability in the last 10 days */
    threat_ip_count_10d: number;
    /** Number of threat IPs seen exploiting this vulnerability in the last 30 days */
    threat_ip_count_30d: number;
  };
}

// ─── v3 IP Lookup Types ──────────────────────────────────────────────────────

/**
 * Business Service Intelligence (BSI) - replaces RIOT in v3
 */
export interface BusinessServiceIntelligence {
  found: boolean;
  category?: string;
  name?: string;
  description?: string;
  explanation?: string;
  last_updated?: string;
  reference?: string;
  trust_level?: string;
}

/**
 * Tag object embedded in v3 IP responses (richer than plain string)
 */
export interface InternetScannerTag {
  id: string;
  slug: string;
  name: string;
  category: string;
  intention: string;
  description: string;
  references: string[];
  recommend_block: boolean;
  cves: string[];
  created_at: string;
  updated_at: string;
}

/**
 * Metadata for an IP in the v3 Internet Scanner Intelligence response
 */
export interface InternetScannerMetadata {
  mobile?: boolean;
  source_country?: string;
  source_country_code?: string;
  source_city?: string;
  region?: string;
  organization?: string;
  rdns?: string;
  asn?: string;
  category?: string;
  os?: string;
  destination_countries?: string[];
  destination_country_codes?: string[];
  destination_cities?: string[];
  destination_asns?: string[];
  single_destination?: boolean;
  carrier?: string;
  datacenter?: string;
  domain?: string;
  rdns_parent?: string;
  rdns_validated?: boolean;
  latitude?: number;
  longitude?: number;
  sensor_count?: number;
  sensor_hits?: number;
}

/**
 * HTTP raw data from v3 responses
 */
export interface RawDataHttp {
  md5?: string;
  cookie_keys?: string[];
  request_authorization?: string[];
  request_cookies?: string[];
  request_header?: string[];
  method?: string[];
  request_origin?: string[];
  host?: string[];
  uri?: string[];
  path?: string[];
  useragent?: string[];
  ja4h?: string[];
}

/**
 * TLS raw data from v3 responses
 */
export interface RawDataTls {
  cipher?: string;
  ja4?: string[];
}

/**
 * SSH raw data from v3 responses
 */
export interface RawDataSsh {
  key?: string[];
  ja4ssh?: string[];
}

/**
 * TCP raw data from v3 responses
 */
export interface RawDataTcp {
  ja4t?: string[];
  ja4l?: string;
}

/**
 * Source raw data from v3 responses
 */
export interface RawDataSource {
  bytes?: number;
}

/**
 * Raw data collected about an IP in v3 responses
 */
export interface InternetScannerRawData {
  scan?: Array<{
    port: number;
    protocol: string;
  }>;
  ja3?: Array<{
    fingerprint: string;
    port: number;
  }>;
  hassh?: Array<{
    fingerprint: string;
    port: number;
  }>;
  http?: RawDataHttp;
  tls?: RawDataTls;
  ssh?: RawDataSsh;
  tcp?: RawDataTcp;
  source?: RawDataSource;
}

/**
 * Internet Scanner Intelligence (ISI) - the core scanning data in v3
 */
export interface InternetScannerIntelligence {
  ip?: string;
  seen?: boolean;
  classification?: string;
  first_seen?: string;
  last_seen?: string;
  last_seen_timestamp?: string[];
  found?: boolean;
  actor?: string;
  bot?: boolean;
  spoofable?: boolean;
  cves?: string[];
  tor?: boolean;
  vpn?: boolean;
  vpn_service?: string;
  metadata?: InternetScannerMetadata;
  tags?: InternetScannerTag[];
  raw_data?: InternetScannerRawData;
}

/**
 * Request metadata included in v3 responses
 */
export interface V3RequestMetadata {
  restricted_fields?: string[];
  message?: string;
}

/**
 * v3 IP context response structure (GET /v3/ip/{ip})
 */
export interface IPContextResponse {
  ip: string;
  business_service_intelligence: BusinessServiceIntelligence;
  internet_scanner_intelligence: InternetScannerIntelligence;
  request_metadata?: V3RequestMetadata;
}

/**
 * v3 IP quick check response (GET /v3/ip/{ip}?quick=true)
 */
export interface IPQuickCheckV3Response {
  ip: string;
  business_service_intelligence: {
    found: boolean;
    trust_level?: string;
  };
  internet_scanner_intelligence: {
    found: boolean;
    classification?: string;
  };
}

/**
 * v3 Multi-IP response (POST /v3/ip)
 */
export interface MultiIPV3Response {
  data: IPContextResponse[];
  request_metadata: V3RequestMetadata & {
    ips_not_found?: string[];
  };
}

// ─── v3 GNQL Types ───────────────────────────────────────────────────────────

/**
 * Pagination metadata common to v3 GNQL responses
 */
export interface GnqlPaginationMetadata {
  complete: boolean;
  scroll?: string;
  query: string;
  adjusted_query?: string;
  restricted_fields?: string[];
  message?: string;
}

/**
 * v3 GNQL query response (GET /v3/gnql)
 */
export interface GnqlQueryResponse {
  data: IPContextResponse[];
  request_metadata: GnqlPaginationMetadata;
}

/**
 * v3 GNQL metadata query response (GET /v3/gnql/metadata)
 * Same shape but results lack raw_data
 */
export interface GnqlMetadataQueryResponse {
  data: IPContextResponse[];
  request_metadata: GnqlPaginationMetadata;
}

/**
 * A single IP record in a timeseries hourly bucket.
 * Note: tags are string[] in timeseries (not rich objects).
 */
export interface GnqlTimeseriesIPRecord {
  ip: string;
  internet_scanner_intelligence?: {
    first_seen?: string;
    last_seen?: string;
    found?: boolean;
    tags?: string[];
    classification?: string;
    actor?: string;
    bot?: boolean;
    vpn?: boolean;
    vpn_service?: string;
    tor?: boolean;
    spoofable?: boolean;
    cves?: string[];
    metadata?: InternetScannerMetadata;
    raw_data?: InternetScannerRawData;
    [key: string]: any;
  };
  business_service_intelligence?: BusinessServiceIntelligence;
  [key: string]: any;
}

/**
 * v3 GNQL timeseries response (GET /v3/gnql/timeseries)
 * Response is a flat dict: keys are timestamp strings (e.g., "2026-03-15-11"),
 * values are arrays of IP records for that hour.
 */
export type GnqlTimeseriesResponse = Record<string, GnqlTimeseriesIPRecord[]>;

/**
 * v3 GNQL timeseries stats response (GET /v3/gnql/timeseries/stats)
 */
export interface GnqlTimeseriesStatsResponse {
  count: number;
  max: number;
  min: number;
  data: Array<{
    date: string;
    count: number;
  }>;
}

// ─── v3 Session Types ─────────────────────────────────────────────────────────

/**
 * A network session captured by GreyNoise sensors.
 * Sessions contain network flow data, protocol details, and enrichment metadata.
 * The full set of fields is dynamic and can be discovered via /v3/sessions/fields.
 */
export interface SessionResponse {
  /** Unique session identifier */
  _id: string;
  /** Timestamp of the first packet in the session */
  firstPacket: string;
  /** Timestamp of the last packet in the session */
  lastPacket: string;
  /** Source IP address */
  "source.ip": string;
  /** Source port number */
  "source.port": number;
  /** Destination IP address */
  "destination.ip": string;
  /** Destination port number */
  "destination.port": number;
  /** Total bytes sent from source */
  "source.bytes": number;
  /** Total packets sent from source */
  "source.packets": number;
  /** Total bytes sent from destination */
  "destination.bytes": number;
  /** Total packets sent from destination */
  "destination.packets": number;
  /** GreyNoise classification of the source IP */
  classification?: string;
  /** Dynamic additional fields */
  [key: string]: any;
}
