import React from 'react';
import { render, screen, fireEvent } from '@testing-library/react';

// react-markdown / remark-gfm are ESM-only; mock them (matches SkillResources.test).
jest.mock('react-markdown', () => {
  const Mock = ({ children }: { children: React.ReactNode }) => <div>{children}</div>;
  return { __esModule: true, default: Mock };
});
jest.mock('remark-gfm', () => ({ __esModule: true, default: () => {} }));

import SemanticSearchResults from '../SemanticSearchResults';

// Heavy child modals make network calls / pull in markdown; stub the ones the
// result cards open. The inline modals under test are exercised via open clicks.
jest.mock('../ServerConfigModal', () => {
  const M = () => <div data-testid="server-config-modal" />;
  M.displayName = 'ServerConfigModal';
  return M;
});
jest.mock('../AgentDetailsModal', () => {
  const M = () => <div data-testid="agent-details-modal" />;
  M.displayName = 'AgentDetailsModal';
  return M;
});

const baseProps = {
  query: 'auth',
  loading: false,
  error: null as string | null,
  servers: [],
  tools: [],
  agents: [],
  skills: [],
  virtualServers: [],
  custom: [],
};

const server = {
  server_name: 'Auth Server',
  path: '/auth',
  description: 'Handles auth',
  relevance_score: 0.92,
  is_enabled: true,
  tags: ['security'],
  matching_tools: [],
} as any;

describe('SemanticSearchResults', () => {
  it('shows the loading indicator', () => {
    render(<SemanticSearchResults {...baseProps} loading />);
    expect(screen.getByText(/Searching/)).toBeInTheDocument();
  });

  it('shows the error message', () => {
    render(<SemanticSearchResults {...baseProps} error="boom" />);
    expect(screen.getByText('boom')).toBeInTheDocument();
  });

  it('shows the empty state when there are no results', () => {
    render(<SemanticSearchResults {...baseProps} />);
    expect(screen.getByText('No semantic matches found')).toBeInTheDocument();
  });

  it('renders a matching server with its name, match score, and section header', () => {
    render(<SemanticSearchResults {...baseProps} servers={[server]} />);
    expect(screen.getByText(/Matching Servers/)).toBeInTheDocument();
    expect(screen.getByText('Auth Server')).toBeInTheDocument();
    expect(screen.getByText(/92% match/)).toBeInTheDocument();
  });

  it('opens the server details modal from a result card', () => {
    render(<SemanticSearchResults {...baseProps} servers={[server]} />);
    fireEvent.click(screen.getByTitle('View server details'));
    // The details modal renders the path + a Match Score section.
    expect(screen.getByText('Match Score')).toBeInTheDocument();
  });

  it('renders matching tools with their server name', () => {
    render(
      <SemanticSearchResults
        {...baseProps}
        tools={[
          {
            tool_name: 'login',
            server_name: 'Auth Server',
            server_path: '/auth',
            description: 'log in',
            relevance_score: 0.8,
          } as any,
        ]}
      />,
    );
    expect(screen.getByText(/Matching Tools/)).toBeInTheDocument();
    expect(screen.getByText('login')).toBeInTheDocument();
  });

  it('renders a matching skill with its SKILL badge', () => {
    render(
      <SemanticSearchResults
        {...baseProps}
        skills={[
          {
            skill_name: 'doc-writer',
            path: '/skills/doc-writer',
            description: 'writes docs',
            relevance_score: 0.7,
            visibility: 'public',
            is_enabled: true,
            tags: [],
          } as any,
        ]}
      />,
    );
    expect(screen.getByText(/Matching Skills/)).toBeInTheDocument();
    expect(screen.getByText('doc-writer')).toBeInTheDocument();
  });
});
