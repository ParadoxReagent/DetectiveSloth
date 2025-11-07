import React, { useEffect, useState } from 'react';
import {
  Shield,
  Target,
  AlertTriangle,
  TrendingUp,
  Database,
  Activity,
  Users,
  FileText
} from 'lucide-react';
import Card from '../components/Card';
import Loading from '../components/Loading';
import { dashboardApi } from '../services/api';
import type { DashboardStatistics, MitreCoverage, Activity as ActivityType } from '../types';
import { formatDistanceToNow } from 'date-fns';

interface StatCardProps {
  title: string;
  value: number | string;
  icon: React.ReactNode;
  trend?: string;
  color?: string;
}

const StatCard: React.FC<StatCardProps> = ({ title, value, icon, trend, color = 'blue' }) => {
  const colorClasses = {
    blue: 'bg-blue-50 text-blue-600',
    green: 'bg-green-50 text-green-600',
    yellow: 'bg-yellow-50 text-yellow-600',
    red: 'bg-red-50 text-red-600',
    purple: 'bg-purple-50 text-purple-600',
  };

  return (
    <Card>
      <div className="flex items-center justify-between">
        <div>
          <p className="text-sm font-medium text-gray-600">{title}</p>
          <p className="mt-2 text-3xl font-bold text-gray-900">{value}</p>
          {trend && (
            <p className="mt-2 text-sm text-gray-500">{trend}</p>
          )}
        </div>
        <div className={`p-3 rounded-lg ${colorClasses[color as keyof typeof colorClasses] || colorClasses.blue}`}>
          {icon}
        </div>
      </div>
    </Card>
  );
};

const Dashboard: React.FC = () => {
  const [statistics, setStatistics] = useState<DashboardStatistics | null>(null);
  const [coverage, setCoverage] = useState<MitreCoverage | null>(null);
  const [recentActivity, setRecentActivity] = useState<ActivityType[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const fetchDashboardData = async () => {
      try {
        setLoading(true);
        const [statsResponse, coverageResponse, activityResponse] = await Promise.all([
          dashboardApi.getStatistics(),
          dashboardApi.getMitreCoverage(),
          dashboardApi.getRecentActivity(10),
        ]);

        setStatistics(statsResponse.data);
        setCoverage(coverageResponse.data);
        setRecentActivity(activityResponse.data);
        setError(null);
      } catch (err) {
        console.error('Error fetching dashboard data:', err);
        setError('Failed to load dashboard data. Please ensure the backend is running.');
      } finally {
        setLoading(false);
      }
    };

    fetchDashboardData();
  }, []);

  if (loading) {
    return <Loading text="Loading dashboard..." />;
  }

  if (error) {
    return (
      <div className="text-center py-12">
        <AlertTriangle className="h-12 w-12 text-red-500 mx-auto mb-4" />
        <p className="text-red-600">{error}</p>
      </div>
    );
  }

  if (!statistics || !coverage) {
    return null;
  }

  const getActivityIcon = (type: string) => {
    switch (type) {
      case 'query_generated':
        return <FileText className="h-4 w-4" />;
      case 'campaign_created':
        return <Target className="h-4 w-4" />;
      case 'threat_intel_added':
        return <AlertTriangle className="h-4 w-4" />;
      default:
        return <Activity className="h-4 w-4" />;
    }
  };

  const getActivityTitle = (activity: ActivityType) => {
    switch (activity.type) {
      case 'query_generated':
        return `Query generated for ${activity.details.platform}`;
      case 'campaign_created':
        return `Campaign created: ${activity.details.name}`;
      case 'threat_intel_added':
        return `New ${activity.details.ioc_type} IOC from ${activity.details.source}`;
      default:
        return activity.type;
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h2 className="text-3xl font-bold text-gray-900">Dashboard</h2>
        <p className="mt-2 text-gray-600">
          Overview of threat hunting capabilities and recent activity
        </p>
      </div>

      {/* Statistics Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        <StatCard
          title="MITRE Techniques"
          value={statistics.totals.techniques}
          icon={<Shield className="h-6 w-6" />}
          trend={`${coverage.coverage_percentage}% covered`}
          color="blue"
        />
        <StatCard
          title="Detection Templates"
          value={statistics.totals.templates}
          icon={<FileText className="h-6 w-6" />}
          trend={`${statistics.totals.templates} total templates`}
          color="green"
        />
        <StatCard
          title="Active Campaigns"
          value={statistics.totals.active_campaigns}
          icon={<Target className="h-6 w-6" />}
          trend={`${statistics.totals.campaigns} total`}
          color="purple"
        />
        <StatCard
          title="High-Risk CVEs"
          value={statistics.totals.high_risk_cves}
          icon={<AlertTriangle className="h-6 w-6" />}
          trend={`${statistics.totals.cves} total CVEs`}
          color="red"
        />
      </div>

      {/* Secondary Stats */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        <StatCard
          title="Recent IOCs (24h)"
          value={statistics.threat_intel.recent_24h}
          icon={<Database className="h-6 w-6" />}
          trend={`${statistics.threat_intel.recent_7d} in last 7 days`}
          color="yellow"
        />
        <StatCard
          title="Queries Generated (7d)"
          value={statistics.query_activity.recent_7d}
          icon={<TrendingUp className="h-6 w-6" />}
          color="blue"
        />
        <StatCard
          title="Active Threat Actors"
          value={statistics.totals.recently_active_actors}
          icon={<Users className="h-6 w-6" />}
          trend={`${statistics.totals.threat_actors} tracked`}
          color="purple"
        />
      </div>

      {/* Coverage and Activity */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* MITRE Coverage */}
        <Card title="MITRE ATT&CK Coverage" subtitle={`${coverage.covered_techniques} of ${coverage.total_techniques} techniques covered`}>
          <div className="space-y-4">
            <div>
              <div className="flex justify-between text-sm text-gray-600 mb-2">
                <span>Coverage Progress</span>
                <span>{coverage.coverage_percentage}%</span>
              </div>
              <div className="w-full bg-gray-200 rounded-full h-2.5">
                <div
                  className="bg-primary-600 h-2.5 rounded-full transition-all"
                  style={{ width: `${coverage.coverage_percentage}%` }}
                ></div>
              </div>
            </div>

            <div className="mt-6">
              <h4 className="text-sm font-semibold text-gray-700 mb-3">Top Covered Tactics</h4>
              <div className="space-y-2">
                {Object.entries(coverage.tactics).slice(0, 5).map(([tactic, techniques]) => (
                  <div key={tactic} className="flex justify-between items-center text-sm">
                    <span className="text-gray-700">{tactic}</span>
                    <span className="text-gray-500">
                      {techniques.filter(t => t.template_count > 0).length} / {techniques.length}
                    </span>
                  </div>
                ))}
              </div>
            </div>

            <div className="mt-6">
              <h4 className="text-sm font-semibold text-gray-700 mb-3">Top Techniques</h4>
              <div className="space-y-2">
                {statistics.top_techniques.slice(0, 5).map((technique) => (
                  <div key={technique.technique_id} className="flex justify-between items-center text-sm">
                    <span className="text-gray-700 font-mono">{technique.technique_id}</span>
                    <span className="text-gray-500">{technique.template_count} templates</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </Card>

        {/* Recent Activity */}
        <Card title="Recent Activity" subtitle="Latest system activity">
          <div className="space-y-3">
            {recentActivity.length === 0 ? (
              <p className="text-gray-500 text-sm text-center py-8">No recent activity</p>
            ) : (
              recentActivity.map((activity, index) => (
                <div
                  key={index}
                  className="flex items-start space-x-3 p-3 bg-gray-50 rounded-lg hover:bg-gray-100 transition-colors"
                >
                  <div className="flex-shrink-0 mt-1 text-gray-600">
                    {getActivityIcon(activity.type)}
                  </div>
                  <div className="flex-1 min-w-0">
                    <p className="text-sm font-medium text-gray-900 truncate">
                      {getActivityTitle(activity)}
                    </p>
                    <p className="text-xs text-gray-500 mt-1">
                      {formatDistanceToNow(new Date(activity.timestamp), { addSuffix: true })}
                    </p>
                  </div>
                </div>
              ))
            )}
          </div>
        </Card>
      </div>

      {/* Platform Breakdown */}
      {Object.keys(statistics.query_activity.platform_breakdown).length > 0 && (
        <Card title="Query Generation by Platform" subtitle="Distribution of generated queries">
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            {Object.entries(statistics.query_activity.platform_breakdown).map(([platform, count]) => (
              <div key={platform} className="text-center p-4 bg-gray-50 rounded-lg">
                <p className="text-2xl font-bold text-gray-900">{count}</p>
                <p className="text-sm text-gray-600 mt-1 capitalize">{platform}</p>
              </div>
            ))}
          </div>
        </Card>
      )}

      {/* IOC Type Breakdown */}
      {Object.keys(statistics.threat_intel.ioc_type_breakdown).length > 0 && (
        <Card title="Threat Intelligence by Type" subtitle="Distribution of IOC types">
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            {Object.entries(statistics.threat_intel.ioc_type_breakdown).map(([type, count]) => (
              <div key={type} className="text-center p-4 bg-gray-50 rounded-lg">
                <p className="text-2xl font-bold text-gray-900">{count}</p>
                <p className="text-sm text-gray-600 mt-1 capitalize">{type}</p>
              </div>
            ))}
          </div>
        </Card>
      )}
    </div>
  );
};

export default Dashboard;
