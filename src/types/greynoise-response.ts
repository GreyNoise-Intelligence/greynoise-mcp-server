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
      os: string;
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

/**
 * Response structure for IP context information from GreyNoise
 */
export interface IPContextResponse {
  /** The IP address */
  ip: string;
  /** When this IP was first observed by GreyNoise */
  first_seen: string;
  /** When this IP was last observed by GreyNoise */
  last_seen: string;
  /** Whether this IP has been observed by GreyNoise */
  seen: boolean;
  /** List of tags associated with this IP */
  tags: string[];
  /** The actor associated with this IP, if any */
  actor: string;
  /** Whether this IP is spoofable */
  spoofable: boolean;
  /** Classification of this IP (e.g., 'malicious', 'benign') */
  classification: string;
  /** List of CVEs associated with this IP's activity */
  cve: string[];
  /** Whether this IP is part of a botnet */
  bot: boolean;
  /** Whether this IP is associated with a VPN service */
  vpn: boolean;
  /** The name of the VPN service, if applicable */
  vpn_service: string;
  /** Additional metadata about the IP */
  metadata: {
    /** Autonomous System Number */
    asn: string;
    /** City location */
    city: string;
    /** Country location */
    country: string;
    /** Two-letter country code */
    country_code: string;
    /** Organization that owns the IP */
    organization: string;
    /** Category of the organization */
    category: string;
    /** Whether this IP is a Tor exit node */
    tor: boolean;
    /** Reverse DNS information */
    rdns: string;
    /** Operating system if detected */
    os: string;
    /** Region location */
    region: string;
    /** Countries this IP has been observed connecting to */
    destination_countries: string[];
    /** Two-letter country codes this IP has been observed connecting to */
    destination_country_codes: string[];
    /** Country where this IP is located */
    source_country: string;
    /** Two-letter country code where this IP is located */
    source_country_code: string;
    /** Number of GreyNoise sensors that have observed this IP */
    sensor_hits: number;
    /** Total number of GreyNoise sensors */
    sensor_count: number;
  };
  /** Raw data collected about this IP */
  raw_data: {
    /** Port scan information */
    scan: Array<{
      /** Port number */
      port: number;
      /** Protocol (e.g., 'tcp', 'udp') */
      protocol: string;
    }>;
    /** Web request information */
    web: Record<string, any>;
    /** JA3 TLS fingerprint information */
    ja3: Array<{
      /** The JA3 fingerprint hash */
      fingerprint: string;
      /** Port on which the TLS connection was observed */
      port: number;
    }>;
    /** HASSH SSH fingerprint information */
    hassh: any[];
  };
}

/**
 * Response structure for IP quick check
 */
export interface IPQuickCheckResponse {
  /** Response code indicating the status of the request */
  code: string;
  /** The IP address that was checked */
  ip: string;
  /** Whether this IP is classified as "noise" (scanning or crawling the internet) */
  noise: boolean;
  /** Whether this IP belongs to a common business service */
  riot: boolean;
}

/**
 * Response structure for checking multiple IPs
 */
export interface MultiIPQuickCheckResponse extends Array<{
  /** Response code indicating the status of the request */
  code: string;
  /** The IP address that was checked */
  ip: string;
  /** Whether this IP is classified as "noise" (scanning or crawling the internet) */
  noise: boolean;
  /** Whether this IP belongs to a common business service */
  riot: boolean;
}> {}

/**
 * Response structure for RIOT IP lookup
 */
export interface RIOTLookupResponse {
  /** The IP address that was looked up */
  ip: string;
  /** Whether this IP belongs to a common business service */
  riot: boolean;
  /** Name of the common business service */
  name?: string;
  /** Category of the common business service */
  category?: string;
  /** Description of the common business service */
  description?: string;
  /** Trust level of the common business service */
  trust_level?: string;
  /** When this RIOT entry was last updated */
  last_updated?: string;
  /** List of services provided by this IP */
  services?: string[];
}
