import axios from 'axios';
import type {
  MitreTechnique,
  ThreatIntel,
  GeneratedQuery,
  HuntCampaign,
  DetectionTemplate,
  DashboardStatistics,
  MitreCoverage,
  Activity,
  QueryGenerationRequest,
  QueryGenerationResponse,
  ThreatActor,
  CVE,
} from '../types';

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000';

const api = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Dashboard APIs
export const dashboardApi = {
  getStatistics: () =>
    api.get<DashboardStatistics>('/api/dashboard/statistics'),

  getMitreCoverage: () =>
    api.get<MitreCoverage>('/api/dashboard/mitre-coverage'),

  getRecentActivity: (limit: number = 20) =>
    api.get<Activity[]>('/api/dashboard/recent-activity', { params: { limit } }),
};

// Techniques APIs
export const techniquesApi = {
  getAll: (params?: { keyword?: string; tactic?: string; platform?: string }) =>
    api.get<MitreTechnique[]>('/api/techniques', { params }),

  getById: (techniqueId: string) =>
    api.get<MitreTechnique>(`/api/techniques/${techniqueId}`),

  getTactics: () =>
    api.get<string[]>('/api/techniques/meta/tactics'),

  getPlatforms: () =>
    api.get<string[]>('/api/techniques/meta/platforms'),

  update: () =>
    api.post('/api/techniques/update'),
};

// Query Generation APIs
export const queriesApi = {
  generate: (request: QueryGenerationRequest) =>
    api.post<QueryGenerationResponse>('/api/queries/generate', request),

  getTemplates: (techniqueId: string) =>
    api.get<DetectionTemplate[]>(`/api/queries/templates/${techniqueId}`),

  addTemplate: (template: Partial<DetectionTemplate>) =>
    api.post<DetectionTemplate>('/api/queries/templates', template),
};

// Enhanced Query APIs
export const enhancedQueriesApi = {
  generateHuntCampaign: (request: any) =>
    api.post('/api/enhanced-queries/hunt-campaign', request),

  generateWithExplanation: (request: any) =>
    api.post('/api/enhanced-queries/query-with-explanation', request),

  getQueryVariations: (techniqueId: string, platform: string) =>
    api.get(`/api/enhanced-queries/query-variations/${techniqueId}/${platform}`),

  getHuntSequence: (techniqueIds: string[]) =>
    api.get('/api/enhanced-queries/hunt-sequence/' + techniqueIds.join(',')),

  getRelatedTechniques: (techniqueId: string) =>
    api.get(`/api/enhanced-queries/related-techniques/${techniqueId}`),
};

// Threat Intel APIs
export const threatIntelApi = {
  getRecent: (params?: { days?: number; ioc_type?: string }) =>
    api.get<ThreatIntel[]>('/api/threat-intel/recent', { params }),

  getByTechnique: (techniqueId: string) =>
    api.get<ThreatIntel[]>(`/api/threat-intel/by-technique/${techniqueId}`),

  updateAll: () =>
    api.post('/api/threat-intel/update'),

  updateFeed: (feed: string) =>
    api.post(`/api/threat-intel/update/${feed}`),
};

// Campaign APIs
export const campaignsApi = {
  getAll: (params?: { status?: string }) =>
    api.get<HuntCampaign[]>('/api/campaigns', { params }),

  getById: (id: number) =>
    api.get<HuntCampaign>(`/api/campaigns/${id}`),

  create: (campaign: Partial<HuntCampaign>) =>
    api.post<HuntCampaign>('/api/campaigns', campaign),

  update: (id: number, updates: Partial<HuntCampaign>) =>
    api.patch<HuntCampaign>(`/api/campaigns/${id}`, updates),

  delete: (id: number) =>
    api.delete(`/api/campaigns/${id}`),
};

// Threat Actor APIs
export const threatActorApi = {
  getAll: (params?: { active_since?: string; targeted_sector?: string }) =>
    api.get<ThreatActor[]>('/api/threat-actors', { params }),

  getByName: (name: string) =>
    api.get<ThreatActor>(`/api/threat-actors/${name}`),

  create: (actor: Partial<ThreatActor>) =>
    api.post<ThreatActor>('/api/threat-actors', actor),

  getRecentlyActive: () =>
    api.get<ThreatActor[]>('/api/threat-actors/active/recent'),
};

// CVE APIs
export const cveApi = {
  getAll: (params?: { exploited_in_wild?: boolean; ransomware_use?: boolean; min_cvss?: number }) =>
    api.get<CVE[]>('/api/cves', { params }),

  getById: (cveId: string) =>
    api.get<CVE>(`/api/cves/${cveId}`),

  getHighRisk: () =>
    api.get<CVE[]>('/api/cves/high-risk'),

  getByTechnique: (techniqueId: string) =>
    api.get<CVE[]>(`/api/cves/by-technique/${techniqueId}`),
};

export default api;
