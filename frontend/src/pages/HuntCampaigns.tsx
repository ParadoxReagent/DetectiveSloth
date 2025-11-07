import React, { useState, useEffect } from 'react';
import { Plus, Target, Calendar, User, Trash2, Edit, Eye } from 'lucide-react';
import Card from '../components/Card';
import Button from '../components/Button';
import Loading from '../components/Loading';
import { campaignsApi } from '../services/api';
import type { HuntCampaign } from '../types';
import { formatDistanceToNow, format } from 'date-fns';

const HuntCampaigns: React.FC = () => {
  const [campaigns, setCampaigns] = useState<HuntCampaign[]>([]);
  const [loading, setLoading] = useState(true);
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [selectedCampaign, setSelectedCampaign] = useState<HuntCampaign | null>(null);
  const [filterStatus, setFilterStatus] = useState<string>('');

  useEffect(() => {
    fetchCampaigns();
  }, [filterStatus]);

  const fetchCampaigns = async () => {
    try {
      setLoading(true);
      const response = await campaignsApi.getAll(
        filterStatus ? { status: filterStatus } : undefined
      );
      setCampaigns(response.data);
    } catch (err) {
      console.error('Error fetching campaigns:', err);
    } finally {
      setLoading(false);
    }
  };

  const handleDeleteCampaign = async (id: number) => {
    if (!window.confirm('Are you sure you want to delete this campaign?')) {
      return;
    }

    try {
      await campaignsApi.delete(id);
      setCampaigns(campaigns.filter((c) => c.id !== id));
    } catch (err) {
      console.error('Error deleting campaign:', err);
      alert('Failed to delete campaign');
    }
  };

  const handleUpdateStatus = async (id: number, status: string) => {
    try {
      const response = await campaignsApi.update(id, { status });
      setCampaigns(campaigns.map((c) => (c.id === id ? response.data : c)));
    } catch (err) {
      console.error('Error updating campaign:', err);
      alert('Failed to update campaign status');
    }
  };

  const getStatusBadge = (status: string) => {
    const statusColors: Record<string, string> = {
      planning: 'bg-gray-100 text-gray-800',
      active: 'bg-blue-100 text-blue-800',
      in_progress: 'bg-yellow-100 text-yellow-800',
      completed: 'bg-green-100 text-green-800',
      cancelled: 'bg-red-100 text-red-800',
    };

    return (
      <span
        className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${
          statusColors[status] || statusColors.planning
        }`}
      >
        {status.replace('_', ' ').toUpperCase()}
      </span>
    );
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex justify-between items-center">
        <div>
          <h2 className="text-3xl font-bold text-gray-900">Hunt Campaigns</h2>
          <p className="mt-2 text-gray-600">
            Manage and track threat hunting campaigns
          </p>
        </div>
        <Button onClick={() => setShowCreateModal(true)}>
          <Plus className="h-4 w-4 mr-2" />
          New Campaign
        </Button>
      </div>

      {/* Filters */}
      <Card>
        <div className="flex items-center space-x-4">
          <label className="text-sm font-medium text-gray-700">Filter by status:</label>
          <select
            value={filterStatus}
            onChange={(e) => setFilterStatus(e.target.value)}
            className="px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-primary-500 focus:border-transparent"
          >
            <option value="">All Statuses</option>
            <option value="planning">Planning</option>
            <option value="active">Active</option>
            <option value="in_progress">In Progress</option>
            <option value="completed">Completed</option>
            <option value="cancelled">Cancelled</option>
          </select>
        </div>
      </Card>

      {/* Campaigns List */}
      {loading ? (
        <Loading text="Loading campaigns..." />
      ) : campaigns.length === 0 ? (
        <Card>
          <div className="text-center py-12">
            <Target className="h-12 w-12 text-gray-400 mx-auto mb-4" />
            <p className="text-gray-600">No campaigns found</p>
            <Button className="mt-4" onClick={() => setShowCreateModal(true)}>
              Create your first campaign
            </Button>
          </div>
        </Card>
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {campaigns.map((campaign) => (
            <Card key={campaign.id}>
              <div className="space-y-4">
                {/* Header */}
                <div className="flex justify-between items-start">
                  <div className="flex-1">
                    <h3 className="text-lg font-semibold text-gray-900">
                      {campaign.name}
                    </h3>
                    <p className="text-sm text-gray-600 mt-1">
                      {campaign.description}
                    </p>
                  </div>
                  {getStatusBadge(campaign.status)}
                </div>

                {/* Details */}
                <div className="space-y-2 text-sm">
                  <div className="flex items-center space-x-2 text-gray-600">
                    <Target className="h-4 w-4" />
                    <span>{campaign.techniques.length} techniques</span>
                  </div>

                  {campaign.threat_actor && (
                    <div className="flex items-center space-x-2 text-gray-600">
                      <User className="h-4 w-4" />
                      <span>{campaign.threat_actor}</span>
                    </div>
                  )}

                  {campaign.analyst && (
                    <div className="flex items-center space-x-2 text-gray-600">
                      <User className="h-4 w-4" />
                      <span>Analyst: {campaign.analyst}</span>
                    </div>
                  )}

                  <div className="flex items-center space-x-2 text-gray-600">
                    <Calendar className="h-4 w-4" />
                    <span>
                      Created {formatDistanceToNow(new Date(campaign.created_at), { addSuffix: true })}
                    </span>
                  </div>
                </div>

                {/* Techniques */}
                <div>
                  <div className="flex flex-wrap gap-1">
                    {campaign.techniques.slice(0, 5).map((technique) => (
                      <span
                        key={technique}
                        className="inline-flex items-center px-2 py-1 rounded-md bg-primary-50 text-primary-700 text-xs font-medium"
                      >
                        {technique}
                      </span>
                    ))}
                    {campaign.techniques.length > 5 && (
                      <span className="inline-flex items-center px-2 py-1 rounded-md bg-gray-100 text-gray-600 text-xs font-medium">
                        +{campaign.techniques.length - 5} more
                      </span>
                    )}
                  </div>
                </div>

                {/* Actions */}
                <div className="flex items-center space-x-2 pt-4 border-t border-gray-200">
                  <select
                    value={campaign.status}
                    onChange={(e) => handleUpdateStatus(campaign.id, e.target.value)}
                    className="flex-1 px-3 py-1.5 text-sm border border-gray-300 rounded-lg focus:ring-2 focus:ring-primary-500 focus:border-transparent"
                  >
                    <option value="planning">Planning</option>
                    <option value="active">Active</option>
                    <option value="in_progress">In Progress</option>
                    <option value="completed">Completed</option>
                    <option value="cancelled">Cancelled</option>
                  </select>

                  <Button
                    size="sm"
                    variant="ghost"
                    onClick={() => setSelectedCampaign(campaign)}
                  >
                    <Eye className="h-4 w-4" />
                  </Button>

                  <Button
                    size="sm"
                    variant="danger"
                    onClick={() => handleDeleteCampaign(campaign.id)}
                  >
                    <Trash2 className="h-4 w-4" />
                  </Button>
                </div>
              </div>
            </Card>
          ))}
        </div>
      )}

      {/* Create Campaign Modal */}
      {showCreateModal && (
        <CreateCampaignModal
          onClose={() => setShowCreateModal(false)}
          onCreated={(campaign) => {
            setCampaigns([campaign, ...campaigns]);
            setShowCreateModal(false);
          }}
        />
      )}

      {/* View Campaign Modal */}
      {selectedCampaign && (
        <ViewCampaignModal
          campaign={selectedCampaign}
          onClose={() => setSelectedCampaign(null)}
        />
      )}
    </div>
  );
};

// Create Campaign Modal Component
interface CreateCampaignModalProps {
  onClose: () => void;
  onCreated: (campaign: HuntCampaign) => void;
}

const CreateCampaignModal: React.FC<CreateCampaignModalProps> = ({ onClose, onCreated }) => {
  const [formData, setFormData] = useState({
    name: '',
    description: '',
    techniques: '',
    threat_actor: '',
    analyst: '',
  });
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();

    try {
      setLoading(true);
      const response = await campaignsApi.create({
        name: formData.name,
        description: formData.description,
        techniques: formData.techniques.split(',').map((t) => t.trim()),
        threat_actor: formData.threat_actor || undefined,
        analyst: formData.analyst || undefined,
        status: 'planning',
      });

      onCreated(response.data);
    } catch (err) {
      console.error('Error creating campaign:', err);
      alert('Failed to create campaign');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
      <div className="bg-white rounded-lg max-w-2xl w-full max-h-[90vh] overflow-y-auto">
        <div className="p-6">
          <h3 className="text-lg font-semibold text-gray-900 mb-4">Create Hunt Campaign</h3>

          <form onSubmit={handleSubmit} className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                Campaign Name *
              </label>
              <input
                type="text"
                required
                value={formData.name}
                onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-primary-500 focus:border-transparent"
                placeholder="e.g., Ransomware Hunt Q1 2024"
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                Description *
              </label>
              <textarea
                required
                value={formData.description}
                onChange={(e) => setFormData({ ...formData, description: e.target.value })}
                rows={3}
                className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-primary-500 focus:border-transparent"
                placeholder="Describe the campaign objectives..."
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                Techniques (comma-separated) *
              </label>
              <input
                type="text"
                required
                value={formData.techniques}
                onChange={(e) => setFormData({ ...formData, techniques: e.target.value })}
                className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-primary-500 focus:border-transparent"
                placeholder="e.g., T1055, T1003, T1059.001"
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                Threat Actor (optional)
              </label>
              <input
                type="text"
                value={formData.threat_actor}
                onChange={(e) => setFormData({ ...formData, threat_actor: e.target.value })}
                className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-primary-500 focus:border-transparent"
                placeholder="e.g., APT29, Lazarus"
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                Analyst (optional)
              </label>
              <input
                type="text"
                value={formData.analyst}
                onChange={(e) => setFormData({ ...formData, analyst: e.target.value })}
                className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-primary-500 focus:border-transparent"
                placeholder="Your name or email"
              />
            </div>

            <div className="flex justify-end space-x-3 pt-4">
              <Button type="button" variant="secondary" onClick={onClose}>
                Cancel
              </Button>
              <Button type="submit" disabled={loading}>
                {loading ? 'Creating...' : 'Create Campaign'}
              </Button>
            </div>
          </form>
        </div>
      </div>
    </div>
  );
};

// View Campaign Modal Component
interface ViewCampaignModalProps {
  campaign: HuntCampaign;
  onClose: () => void;
}

const ViewCampaignModal: React.FC<ViewCampaignModalProps> = ({ campaign, onClose }) => {
  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
      <div className="bg-white rounded-lg max-w-3xl w-full max-h-[90vh] overflow-y-auto">
        <div className="p-6">
          <div className="flex justify-between items-start mb-6">
            <h3 className="text-2xl font-bold text-gray-900">{campaign.name}</h3>
            <button
              onClick={onClose}
              className="text-gray-400 hover:text-gray-600"
            >
              <svg className="h-6 w-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
              </svg>
            </button>
          </div>

          <div className="space-y-6">
            <div>
              <h4 className="text-sm font-semibold text-gray-700 mb-2">Status</h4>
              <div className="inline-flex items-center px-3 py-1 rounded-full text-sm font-medium bg-blue-100 text-blue-800">
                {campaign.status.replace('_', ' ').toUpperCase()}
              </div>
            </div>

            <div>
              <h4 className="text-sm font-semibold text-gray-700 mb-2">Description</h4>
              <p className="text-gray-600">{campaign.description}</p>
            </div>

            <div>
              <h4 className="text-sm font-semibold text-gray-700 mb-2">Techniques ({campaign.techniques.length})</h4>
              <div className="flex flex-wrap gap-2">
                {campaign.techniques.map((technique) => (
                  <span
                    key={technique}
                    className="inline-flex items-center px-3 py-1 rounded-md bg-primary-50 text-primary-700 text-sm font-medium"
                  >
                    {technique}
                  </span>
                ))}
              </div>
            </div>

            {campaign.threat_actor && (
              <div>
                <h4 className="text-sm font-semibold text-gray-700 mb-2">Threat Actor</h4>
                <p className="text-gray-600">{campaign.threat_actor}</p>
              </div>
            )}

            {campaign.analyst && (
              <div>
                <h4 className="text-sm font-semibold text-gray-700 mb-2">Analyst</h4>
                <p className="text-gray-600">{campaign.analyst}</p>
              </div>
            )}

            <div className="grid grid-cols-2 gap-4">
              <div>
                <h4 className="text-sm font-semibold text-gray-700 mb-2">Created</h4>
                <p className="text-gray-600">
                  {format(new Date(campaign.created_at), 'PPpp')}
                </p>
              </div>

              {campaign.updated_at && (
                <div>
                  <h4 className="text-sm font-semibold text-gray-700 mb-2">Last Updated</h4>
                  <p className="text-gray-600">
                    {format(new Date(campaign.updated_at), 'PPpp')}
                  </p>
                </div>
              )}
            </div>

            {campaign.findings && Object.keys(campaign.findings).length > 0 && (
              <div>
                <h4 className="text-sm font-semibold text-gray-700 mb-2">Findings</h4>
                <pre className="bg-gray-50 p-4 rounded-lg text-sm overflow-x-auto">
                  {JSON.stringify(campaign.findings, null, 2)}
                </pre>
              </div>
            )}
          </div>

          <div className="flex justify-end mt-6 pt-6 border-t border-gray-200">
            <Button onClick={onClose}>Close</Button>
          </div>
        </div>
      </div>
    </div>
  );
};

export default HuntCampaigns;
