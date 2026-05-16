import { useState, useEffect, useCallback } from 'react';
import axios from 'axios';


/**
 * Peer registry configuration from the backend API.
 */
export interface PeerRegistry {
  peer_id: string;
  name: string;
  endpoint: string;
  enabled: boolean;
  sync_mode: 'all' | 'whitelist' | 'tag_filter';
  whitelist_servers: string[];
  whitelist_agents: string[];
  tag_filters: string[];
  sync_interval_minutes: number;
  sync_local_servers?: boolean;
  federation_token?: string | null;
  expected_client_id?: string | null;
  expected_issuer?: string | null;
  created_at?: string | null;
  updated_at?: string | null;
}


/**
 * Peer sync status from the backend API.
 */
export interface PeerSyncStatus {
  peer_id: string;
  is_healthy: boolean;
  last_health_check?: string | null;
  last_successful_sync?: string | null;
  last_sync_attempt?: string | null;
  current_generation: number;
  total_servers_synced: number;
  total_agents_synced: number;
  sync_in_progress: boolean;
  consecutive_failures: number;
}


/**
 * Sync result from triggering a sync operation.
 */
export interface SyncResult {
  success: boolean;
  peer_id: string;
  servers_synced: number;
  agents_synced: number;
  servers_orphaned: number;
  agents_orphaned: number;
  error_message?: string | null;
  duration_seconds: number;
  new_generation: number;
}


/**
 * Form data for creating or updating a peer.
 */
export interface PeerFormData {
  peer_id: string;
  name: string;
  endpoint: string;
  enabled: boolean;
  sync_mode: 'all' | 'whitelist' | 'tag_filter';
  whitelist_servers: string[];
  whitelist_agents: string[];
  tag_filters: string[];
  sync_interval_minutes: number;
  sync_local_servers?: boolean;
  federation_token?: string;
}


/**
 * Peer with sync status combined for list display.
 */
export interface PeerWithStatus extends PeerRegistry {
  syncStatus?: PeerSyncStatus | null;
}


/**
 * Return type for the useFederationPeers hook.
 */
interface UseFederationPeersReturn {
  peers: PeerWithStatus[];
  isLoading: boolean;
  error: string | null;
  refetch: () => Promise<void>;
  hasPeers: boolean;
}


/**
 * Fetch sync status for a single peer.
 * Returns null on error to avoid failing the whole list.
 */
async function fetchPeerStatus(peerId: string): Promise<PeerSyncStatus | null> {
  try {
    const response = await axios.get(`/api/peers/${peerId}/status`);
    return response.data;
  } catch {
    return null;
  }
}


/**
 * Hook for fetching and managing federation peers.
 *
 * Provides the list of configured peer registries with sync status and loading/error states.
 */
export function useFederationPeers(): UseFederationPeersReturn {
  const [peers, setPeers] = useState<PeerWithStatus[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchPeers = useCallback(async () => {
    try {
      setIsLoading(true);
      setError(null);

      const response = await axios.get('/api/peers');
      const peerList: PeerRegistry[] = response.data || [];

      // Fetch sync status for all peers in parallel
      const statusPromises = peerList.map((peer) => fetchPeerStatus(peer.peer_id));
      const statuses = await Promise.all(statusPromises);

      // Combine peers with their sync status
      const peersWithStatus: PeerWithStatus[] = peerList.map((peer, index) => ({
        ...peer,
        syncStatus: statuses[index],
      }));

      setPeers(peersWithStatus);
    } catch (err: any) {
      console.error('Failed to fetch federation peers:', err);
      setError(
        err.response?.data?.detail ||
        err.message ||
        'Failed to fetch peers'
      );
      setPeers([]);
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchPeers();
  }, [fetchPeers]);

  return {
    peers,
    isLoading,
    error,
    refetch: fetchPeers,
    hasPeers: peers.length > 0,
  };
}


/**
 * Return type for the useFederationPeer hook.
 */
interface UseFederationPeerReturn {
  peer: PeerRegistry | null;
  status: PeerSyncStatus | null;
  isLoading: boolean;
  error: string | null;
  refetch: () => Promise<void>;
}


/**
 * Hook for fetching a single federation peer by ID.
 *
 * @param peerId - The peer ID to fetch, or undefined to skip fetching
 */
export function useFederationPeer(peerId: string | undefined): UseFederationPeerReturn {
  const [peer, setPeer] = useState<PeerRegistry | null>(null);
  const [status, setStatus] = useState<PeerSyncStatus | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const fetchPeer = useCallback(async () => {
    if (!peerId) {
      setPeer(null);
      setStatus(null);
      return;
    }

    try {
      setIsLoading(true);
      setError(null);

      // Fetch peer config and status in parallel
      const [peerResponse, statusResponse] = await Promise.all([
        axios.get(`/api/peers/${peerId}`),
        axios.get(`/api/peers/${peerId}/status`).catch(() => ({ data: null })),
      ]);

      setPeer(peerResponse.data);
      setStatus(statusResponse.data);
    } catch (err: any) {
      console.error(`Failed to fetch peer ${peerId}:`, err);
      setError(
        err.response?.data?.detail ||
        err.message ||
        'Failed to fetch peer'
      );
      setPeer(null);
      setStatus(null);
    } finally {
      setIsLoading(false);
    }
  }, [peerId]);

  useEffect(() => {
    fetchPeer();
  }, [fetchPeer]);

  return {
    peer,
    status,
    isLoading,
    error,
    refetch: fetchPeer,
  };
}


/**
 * API functions for peer management operations.
 */
export async function createPeer(data: PeerFormData): Promise<PeerRegistry> {
  const response = await axios.post('/api/peers', data);
  return response.data;
}


export async function updatePeer(
  peerId: string,
  updates: Partial<PeerFormData>
): Promise<PeerRegistry> {
  const response = await axios.put(`/api/peers/${peerId}`, updates);
  return response.data;
}


export async function deletePeer(peerId: string): Promise<void> {
  await axios.delete(`/api/peers/${peerId}`);
}


export async function syncPeer(peerId: string): Promise<SyncResult> {
  const response = await axios.post(`/api/peers/${peerId}/sync`);
  return response.data;
}


export async function enablePeer(peerId: string): Promise<PeerRegistry> {
  const response = await axios.post(`/api/peers/${peerId}/enable`);
  return response.data;
}


export async function disablePeer(peerId: string): Promise<PeerRegistry> {
  const response = await axios.post(`/api/peers/${peerId}/disable`);
  return response.data;
}
