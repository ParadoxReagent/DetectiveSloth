import React, { useState, useEffect } from 'react';
import { FileText, Search, Filter, Code } from 'lucide-react';
import Card from '../components/Card';
import Button from '../components/Button';
import Loading from '../components/Loading';
import { techniquesApi, queriesApi } from '../services/api';
import type { MitreTechnique, DetectionTemplate } from '../types';

const Templates: React.FC = () => {
  const [techniques, setTechniques] = useState<MitreTechnique[]>([]);
  const [selectedTechnique, setSelectedTechnique] = useState<MitreTechnique | null>(null);
  const [templates, setTemplates] = useState<DetectionTemplate[]>([]);
  const [searchQuery, setSearchQuery] = useState('');
  const [platformFilter, setPlatformFilter] = useState<string>('');
  const [loading, setLoading] = useState(true);
  const [loadingTemplates, setLoadingTemplates] = useState(false);

  useEffect(() => {
    const fetchTechniques = async () => {
      try {
        setLoading(true);
        const response = await techniquesApi.getAll();
        setTechniques(response.data);
      } catch (err) {
        console.error('Error fetching techniques:', err);
      } finally {
        setLoading(false);
      }
    };

    fetchTechniques();
  }, []);

  const fetchTemplatesForTechnique = async (techniqueId: string) => {
    try {
      setLoadingTemplates(true);
      const response = await queriesApi.getTemplates(techniqueId);
      setTemplates(response.data);
    } catch (err) {
      console.error('Error fetching templates:', err);
      setTemplates([]);
    } finally {
      setLoadingTemplates(false);
    }
  };

  const handleTechniqueSelect = (technique: MitreTechnique) => {
    setSelectedTechnique(technique);
    fetchTemplatesForTechnique(technique.technique_id);
  };

  const filteredTechniques = techniques.filter((technique) => {
    const matchesSearch =
      !searchQuery ||
      technique.technique_id.toLowerCase().includes(searchQuery.toLowerCase()) ||
      technique.name.toLowerCase().includes(searchQuery.toLowerCase());

    return matchesSearch;
  });

  const filteredTemplates = templates.filter((template) => {
    return !platformFilter || template.platform === platformFilter;
  });

  const getPlatformBadge = (platform: string) => {
    const platformColors: Record<string, string> = {
      defender: 'bg-blue-100 text-blue-800',
      crowdstrike: 'bg-red-100 text-red-800',
      carbonblack: 'bg-green-100 text-green-800',
      sentinelone: 'bg-purple-100 text-purple-800',
    };

    const platformNames: Record<string, string> = {
      defender: 'Microsoft Defender',
      crowdstrike: 'CrowdStrike',
      carbonblack: 'Carbon Black',
      sentinelone: 'SentinelOne',
    };

    return (
      <span
        className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${
          platformColors[platform] || 'bg-gray-100 text-gray-800'
        }`}
      >
        {platformNames[platform] || platform}
      </span>
    );
  };

  const getConfidenceBadge = (confidence: string) => {
    const confidenceColors: Record<string, string> = {
      high: 'bg-green-100 text-green-800',
      medium: 'bg-yellow-100 text-yellow-800',
      low: 'bg-red-100 text-red-800',
    };

    return (
      <span
        className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${
          confidenceColors[confidence] || 'bg-gray-100 text-gray-800'
        }`}
      >
        {confidence.toUpperCase()}
      </span>
    );
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h2 className="text-3xl font-bold text-gray-900">Detection Templates</h2>
        <p className="mt-2 text-gray-600">
          Browse and manage query templates for MITRE ATT&CK techniques
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Technique List */}
        <div className="lg:col-span-1">
          <Card title="MITRE Techniques">
            <div className="space-y-4">
              {/* Search */}
              <div className="relative">
                <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-gray-400" />
                <input
                  type="text"
                  placeholder="Search techniques..."
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  className="w-full pl-10 pr-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-primary-500 focus:border-transparent"
                />
              </div>

              {/* Technique List */}
              <div className="space-y-2 max-h-[600px] overflow-y-auto">
                {loading ? (
                  <Loading text="Loading techniques..." />
                ) : filteredTechniques.length === 0 ? (
                  <p className="text-sm text-gray-500 text-center py-4">
                    No techniques found
                  </p>
                ) : (
                  filteredTechniques.map((technique) => (
                    <button
                      key={technique.technique_id}
                      onClick={() => handleTechniqueSelect(technique)}
                      className={`w-full text-left p-3 rounded-lg transition-colors ${
                        selectedTechnique?.technique_id === technique.technique_id
                          ? 'bg-primary-50 border-primary-200 border'
                          : 'bg-gray-50 hover:bg-gray-100'
                      }`}
                    >
                      <p className="text-sm font-medium text-gray-900">
                        {technique.technique_id}
                      </p>
                      <p className="text-xs text-gray-600 mt-1 line-clamp-2">
                        {technique.name}
                      </p>
                    </button>
                  ))
                )}
              </div>
            </div>
          </Card>
        </div>

        {/* Template Details */}
        <div className="lg:col-span-2">
          {!selectedTechnique ? (
            <Card>
              <div className="text-center py-12">
                <FileText className="h-12 w-12 text-gray-400 mx-auto mb-4" />
                <p className="text-gray-600">
                  Select a technique to view its templates
                </p>
              </div>
            </Card>
          ) : (
            <div className="space-y-6">
              {/* Technique Info */}
              <Card>
                <div className="space-y-4">
                  <div>
                    <div className="flex items-center justify-between mb-2">
                      <h3 className="text-lg font-semibold text-gray-900">
                        {selectedTechnique.technique_id}
                      </h3>
                      <span className="text-sm text-gray-500">
                        {templates.length} template{templates.length !== 1 ? 's' : ''}
                      </span>
                    </div>
                    <h4 className="text-base font-medium text-gray-700">
                      {selectedTechnique.name}
                    </h4>
                  </div>

                  <p className="text-sm text-gray-600">
                    {selectedTechnique.description}
                  </p>

                  <div className="grid grid-cols-2 gap-4 text-sm">
                    <div>
                      <span className="font-medium text-gray-700">Tactics:</span>
                      <div className="mt-1 flex flex-wrap gap-1">
                        {selectedTechnique.tactics.map((tactic) => (
                          <span
                            key={tactic}
                            className="inline-block px-2 py-1 bg-gray-100 text-gray-700 rounded text-xs"
                          >
                            {tactic}
                          </span>
                        ))}
                      </div>
                    </div>

                    <div>
                      <span className="font-medium text-gray-700">Platforms:</span>
                      <div className="mt-1 flex flex-wrap gap-1">
                        {selectedTechnique.platforms.map((platform) => (
                          <span
                            key={platform}
                            className="inline-block px-2 py-1 bg-gray-100 text-gray-700 rounded text-xs"
                          >
                            {platform}
                          </span>
                        ))}
                      </div>
                    </div>
                  </div>
                </div>
              </Card>

              {/* Platform Filter */}
              <Card>
                <div className="flex items-center space-x-4">
                  <Filter className="h-4 w-4 text-gray-600" />
                  <label className="text-sm font-medium text-gray-700">
                    Filter by platform:
                  </label>
                  <select
                    value={platformFilter}
                    onChange={(e) => setPlatformFilter(e.target.value)}
                    className="px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-primary-500 focus:border-transparent"
                  >
                    <option value="">All Platforms</option>
                    <option value="defender">Microsoft Defender</option>
                    <option value="crowdstrike">CrowdStrike</option>
                    <option value="carbonblack">Carbon Black</option>
                    <option value="sentinelone">SentinelOne</option>
                  </select>
                </div>
              </Card>

              {/* Templates */}
              {loadingTemplates ? (
                <Loading text="Loading templates..." />
              ) : filteredTemplates.length === 0 ? (
                <Card>
                  <div className="text-center py-12">
                    <Code className="h-12 w-12 text-gray-400 mx-auto mb-4" />
                    <p className="text-gray-600">
                      {platformFilter
                        ? `No templates found for ${platformFilter}`
                        : 'No templates available for this technique'}
                    </p>
                  </div>
                </Card>
              ) : (
                <div className="space-y-4">
                  {filteredTemplates.map((template) => (
                    <Card key={template.id}>
                      <div className="space-y-4">
                        {/* Header */}
                        <div className="flex items-center justify-between">
                          <div className="flex items-center space-x-3">
                            {getPlatformBadge(template.platform)}
                            {getConfidenceBadge(template.confidence)}
                          </div>
                          {template.created_by && (
                            <span className="text-xs text-gray-500">
                              by {template.created_by}
                            </span>
                          )}
                        </div>

                        {/* Query Template */}
                        <div>
                          <pre className="query-output whitespace-pre-wrap text-xs">
                            {template.query_template}
                          </pre>
                        </div>

                        {/* Metadata */}
                        <div className="pt-4 border-t border-gray-200 space-y-2 text-sm">
                          {template.data_sources_required.length > 0 && (
                            <div>
                              <span className="font-medium text-gray-700">
                                Data Sources:
                              </span>
                              <span className="ml-2 text-gray-600">
                                {template.data_sources_required.join(', ')}
                              </span>
                            </div>
                          )}

                          {template.false_positive_notes && (
                            <div>
                              <span className="font-medium text-gray-700">
                                False Positive Notes:
                              </span>
                              <p className="mt-1 text-gray-600">
                                {template.false_positive_notes}
                              </p>
                            </div>
                          )}

                          {template.variables && (
                            <div>
                              <span className="font-medium text-gray-700">
                                Variables:
                              </span>
                              <pre className="mt-1 text-xs bg-gray-50 p-2 rounded">
                                {JSON.stringify(template.variables, null, 2)}
                              </pre>
                            </div>
                          )}
                        </div>
                      </div>
                    </Card>
                  ))}
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default Templates;
