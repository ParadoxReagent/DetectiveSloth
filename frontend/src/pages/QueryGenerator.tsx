import React, { useState, useEffect } from 'react';
import { Search, Play, Copy, Check, Download, AlertCircle } from 'lucide-react';
import Card from '../components/Card';
import Button from '../components/Button';
import Loading from '../components/Loading';
import { techniquesApi, queriesApi, threatIntelApi } from '../services/api';
import type { MitreTechnique, QueryGenerationResponse } from '../types';

const QueryGenerator: React.FC = () => {
  const [techniques, setTechniques] = useState<MitreTechnique[]>([]);
  const [selectedTechniques, setSelectedTechniques] = useState<string[]>([]);
  const [selectedPlatforms, setSelectedPlatforms] = useState<string[]>(['defender']);
  const [timeframe, setTimeframe] = useState('7d');
  const [includeIOCs, setIncludeIOCs] = useState(true);
  const [generatedQueries, setGeneratedQueries] = useState<any[]>([]);
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedTactic, setSelectedTactic] = useState<string>('');
  const [tactics, setTactics] = useState<string[]>([]);
  const [loading, setLoading] = useState(false);
  const [loadingTechniques, setLoadingTechniques] = useState(true);
  const [copiedIndex, setCopiedIndex] = useState<number | null>(null);
  const [error, setError] = useState<string | null>(null);

  const platforms = [
    { id: 'defender', name: 'Microsoft Defender' },
    { id: 'crowdstrike', name: 'CrowdStrike' },
    { id: 'carbonblack', name: 'Carbon Black' },
    { id: 'sentinelone', name: 'SentinelOne' },
  ];

  useEffect(() => {
    const fetchData = async () => {
      try {
        setLoadingTechniques(true);
        const [techniquesResponse, tacticsResponse] = await Promise.all([
          techniquesApi.getAll(),
          techniquesApi.getTactics(),
        ]);
        setTechniques(techniquesResponse.data);
        setTactics(tacticsResponse.data);
      } catch (err) {
        console.error('Error fetching techniques:', err);
        setError('Failed to load techniques');
      } finally {
        setLoadingTechniques(false);
      }
    };

    fetchData();
  }, []);

  const filteredTechniques = techniques.filter((technique) => {
    const matchesSearch =
      !searchQuery ||
      technique.technique_id.toLowerCase().includes(searchQuery.toLowerCase()) ||
      technique.name.toLowerCase().includes(searchQuery.toLowerCase());

    const matchesTactic =
      !selectedTactic ||
      technique.tactics.includes(selectedTactic);

    return matchesSearch && matchesTactic;
  });

  const handleTechniqueToggle = (techniqueId: string) => {
    setSelectedTechniques((prev) =>
      prev.includes(techniqueId)
        ? prev.filter((id) => id !== techniqueId)
        : [...prev, techniqueId]
    );
  };

  const handlePlatformToggle = (platform: string) => {
    setSelectedPlatforms((prev) =>
      prev.includes(platform)
        ? prev.filter((p) => p !== platform)
        : [...prev, platform]
    );
  };

  const handleGenerateQueries = async () => {
    if (selectedTechniques.length === 0) {
      setError('Please select at least one technique');
      return;
    }

    if (selectedPlatforms.length === 0) {
      setError('Please select at least one platform');
      return;
    }

    try {
      setLoading(true);
      setError(null);

      const response = await queriesApi.generate({
        technique_ids: selectedTechniques,
        platforms: selectedPlatforms,
        timeframe,
        include_iocs: includeIOCs,
      });

      setGeneratedQueries(response.data.queries || []);
    } catch (err: any) {
      console.error('Error generating queries:', err);
      setError(err.response?.data?.detail || 'Failed to generate queries');
    } finally {
      setLoading(false);
    }
  };

  const handleCopyQuery = async (query: string, index: number) => {
    try {
      await navigator.clipboard.writeText(query);
      setCopiedIndex(index);
      setTimeout(() => setCopiedIndex(null), 2000);
    } catch (err) {
      console.error('Failed to copy query:', err);
    }
  };

  const handleDownloadQuery = (query: string, platform: string) => {
    const blob = new Blob([query], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `query_${platform}_${Date.now()}.txt`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h2 className="text-3xl font-bold text-gray-900">Query Generator</h2>
        <p className="mt-2 text-gray-600">
          Generate platform-specific threat hunting queries from MITRE ATT&CK techniques
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Technique Selection */}
        <div className="lg:col-span-1">
          <Card title="Select Techniques" subtitle={`${selectedTechniques.length} selected`}>
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

              {/* Tactic Filter */}
              <select
                value={selectedTactic}
                onChange={(e) => setSelectedTactic(e.target.value)}
                className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-primary-500 focus:border-transparent"
              >
                <option value="">All Tactics</option>
                {tactics.map((tactic) => (
                  <option key={tactic} value={tactic}>
                    {tactic}
                  </option>
                ))}
              </select>

              {/* Technique List */}
              <div className="space-y-2 max-h-96 overflow-y-auto">
                {loadingTechniques ? (
                  <Loading text="Loading techniques..." />
                ) : filteredTechniques.length === 0 ? (
                  <p className="text-sm text-gray-500 text-center py-4">
                    No techniques found
                  </p>
                ) : (
                  filteredTechniques.map((technique) => (
                    <label
                      key={technique.technique_id}
                      className="flex items-start space-x-3 p-3 bg-gray-50 rounded-lg hover:bg-gray-100 cursor-pointer transition-colors"
                    >
                      <input
                        type="checkbox"
                        checked={selectedTechniques.includes(technique.technique_id)}
                        onChange={() => handleTechniqueToggle(technique.technique_id)}
                        className="mt-1 h-4 w-4 text-primary-600 focus:ring-primary-500 border-gray-300 rounded"
                      />
                      <div className="flex-1 min-w-0">
                        <p className="text-sm font-medium text-gray-900">
                          {technique.technique_id}
                        </p>
                        <p className="text-xs text-gray-600 mt-1 truncate">
                          {technique.name}
                        </p>
                      </div>
                    </label>
                  ))
                )}
              </div>
            </div>
          </Card>
        </div>

        {/* Configuration & Results */}
        <div className="lg:col-span-2 space-y-6">
          {/* Configuration */}
          <Card title="Query Configuration">
            <div className="space-y-6">
              {/* Platform Selection */}
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-3">
                  Target Platforms
                </label>
                <div className="grid grid-cols-2 gap-3">
                  {platforms.map((platform) => (
                    <label
                      key={platform.id}
                      className="flex items-center space-x-3 p-3 bg-gray-50 rounded-lg hover:bg-gray-100 cursor-pointer transition-colors"
                    >
                      <input
                        type="checkbox"
                        checked={selectedPlatforms.includes(platform.id)}
                        onChange={() => handlePlatformToggle(platform.id)}
                        className="h-4 w-4 text-primary-600 focus:ring-primary-500 border-gray-300 rounded"
                      />
                      <span className="text-sm font-medium text-gray-900">
                        {platform.name}
                      </span>
                    </label>
                  ))}
                </div>
              </div>

              {/* Timeframe */}
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">
                  Timeframe
                </label>
                <select
                  value={timeframe}
                  onChange={(e) => setTimeframe(e.target.value)}
                  className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-primary-500 focus:border-transparent"
                >
                  <option value="1h">Last 1 hour</option>
                  <option value="24h">Last 24 hours</option>
                  <option value="7d">Last 7 days</option>
                  <option value="30d">Last 30 days</option>
                  <option value="90d">Last 90 days</option>
                </select>
              </div>

              {/* IOC Inclusion */}
              <div>
                <label className="flex items-center space-x-3">
                  <input
                    type="checkbox"
                    checked={includeIOCs}
                    onChange={(e) => setIncludeIOCs(e.target.checked)}
                    className="h-4 w-4 text-primary-600 focus:ring-primary-500 border-gray-300 rounded"
                  />
                  <span className="text-sm font-medium text-gray-700">
                    Include threat intelligence IOCs
                  </span>
                </label>
              </div>

              {/* Error Display */}
              {error && (
                <div className="flex items-center space-x-2 p-3 bg-red-50 border border-red-200 rounded-lg">
                  <AlertCircle className="h-5 w-5 text-red-600 flex-shrink-0" />
                  <p className="text-sm text-red-600">{error}</p>
                </div>
              )}

              {/* Generate Button */}
              <Button
                onClick={handleGenerateQueries}
                disabled={loading || selectedTechniques.length === 0}
                className="w-full"
                size="lg"
              >
                {loading ? (
                  <>
                    <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-white mr-2"></div>
                    Generating...
                  </>
                ) : (
                  <>
                    <Play className="h-4 w-4 mr-2" />
                    Generate Queries
                  </>
                )}
              </Button>
            </div>
          </Card>

          {/* Generated Queries */}
          {generatedQueries.length > 0 && (
            <div className="space-y-4">
              <h3 className="text-lg font-semibold text-gray-900">
                Generated Queries ({generatedQueries.length})
              </h3>

              {generatedQueries.map((queryData, index) => (
                <Card
                  key={index}
                  title={`${queryData.platform.charAt(0).toUpperCase() + queryData.platform.slice(1)} Query`}
                  subtitle={`Techniques: ${queryData.technique_ids.join(', ')}`}
                  action={
                    <div className="flex space-x-2">
                      <Button
                        size="sm"
                        variant="ghost"
                        onClick={() => handleCopyQuery(queryData.query, index)}
                      >
                        {copiedIndex === index ? (
                          <>
                            <Check className="h-4 w-4 mr-1" />
                            Copied
                          </>
                        ) : (
                          <>
                            <Copy className="h-4 w-4 mr-1" />
                            Copy
                          </>
                        )}
                      </Button>
                      <Button
                        size="sm"
                        variant="ghost"
                        onClick={() => handleDownloadQuery(queryData.query, queryData.platform)}
                      >
                        <Download className="h-4 w-4 mr-1" />
                        Download
                      </Button>
                    </div>
                  }
                >
                  <pre className="query-output whitespace-pre-wrap">
                    {queryData.query}
                  </pre>

                  {queryData.metadata && (
                    <div className="mt-4 pt-4 border-t border-gray-200">
                      <div className="grid grid-cols-2 gap-4 text-sm">
                        {queryData.metadata.confidence && (
                          <div>
                            <span className="font-medium text-gray-700">Confidence:</span>
                            <span className="ml-2 text-gray-600 capitalize">
                              {queryData.metadata.confidence}
                            </span>
                          </div>
                        )}
                        {queryData.metadata.data_sources && (
                          <div>
                            <span className="font-medium text-gray-700">Data Sources:</span>
                            <span className="ml-2 text-gray-600">
                              {queryData.metadata.data_sources.join(', ')}
                            </span>
                          </div>
                        )}
                      </div>
                    </div>
                  )}
                </Card>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default QueryGenerator;
