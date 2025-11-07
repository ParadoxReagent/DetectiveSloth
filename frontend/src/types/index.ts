// API Types
export interface MitreTechnique {
  id: number;
  technique_id: string;
  name: string;
  description: string;
  tactics: string[];
  platforms: string[];
  data_sources: string[];
  detection_notes?: string;
  mitigation_notes?: string;
}

export interface ThreatIntel {
  id: number;
  source: string;
  ioc_type: string;
  ioc_value: string;
  context?: any;
  associated_techniques: string[];
  confidence_score?: number;
  first_seen: string;
  last_seen: string;
  tags: string[];
}

export interface GeneratedQuery {
  id: number;
  technique_ids: string[];
  platform: string;
  query_text: string;
  metadata: any;
  created_at: string;
  executed?: boolean;
  results_count?: number;
}

export interface HuntCampaign {
  id: number;
  name: string;
  description: string;
  techniques: string[];
  threat_actor?: string;
  start_date?: string;
  end_date?: string;
  status: string;
  findings?: any;
  analyst?: string;
  created_at: string;
  updated_at?: string;
}

export interface DetectionTemplate {
  id: number;
  technique_id: string;
  platform: string;
  query_template: string;
  variables?: any;
  confidence: string;
  false_positive_notes?: string;
  data_sources_required: string[];
  created_by?: string;
  created_at: string;
}

export interface DashboardStatistics {
  totals: {
    techniques: number;
    templates: number;
    campaigns: number;
    active_campaigns: number;
    cves: number;
    high_risk_cves: number;
    threat_actors: number;
    recently_active_actors: number;
  };
  threat_intel: {
    recent_24h: number;
    recent_7d: number;
    ioc_type_breakdown: Record<string, number>;
  };
  query_activity: {
    recent_7d: number;
    platform_breakdown: Record<string, number>;
  };
  top_techniques: Array<{
    technique_id: string;
    template_count: number;
  }>;
  last_updated: string;
}

export interface MitreCoverage {
  coverage_percentage: number;
  total_techniques: number;
  covered_techniques: number;
  tactics: Record<string, Array<{
    technique_id: string;
    name: string;
    template_count: number;
    platforms: string[];
  }>>;
}

export interface Activity {
  type: string;
  timestamp: string;
  details: any;
}

export interface QueryGenerationRequest {
  technique_ids: string[];
  platforms: string[];
  timeframe?: string;
  include_iocs?: boolean;
}

export interface QueryGenerationResponse {
  queries: Array<{
    platform: string;
    query: string;
    technique_ids: string[];
    metadata: any;
  }>;
}

export interface ThreatActor {
  id: number;
  name: string;
  aliases: string[];
  actor_type?: string;
  motivation?: string;
  techniques: string[];
  tactics: string[];
  targeted_sectors: string[];
  targeted_countries: string[];
  first_seen?: string;
  last_activity?: string;
  sophistication?: string;
  description?: string;
}

export interface CVE {
  id: number;
  cve_id: string;
  description?: string;
  cvss_score?: number;
  severity?: string;
  exploited_in_wild: boolean;
  ransomware_use: boolean;
  associated_techniques: string[];
  remediation_deadline?: string;
  vendor_name?: string;
  product?: string;
  published_date?: string;
}
