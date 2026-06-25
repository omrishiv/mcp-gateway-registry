import React from 'react';
import { render, screen, fireEvent } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import RegisterPage from '../RegisterPage';

/**
 * Render-level safety net for RegisterPage, written before adopting the shared
 * form-field primitives. Pins the tab/mode structure and key fields so the
 * refactor can't silently drop a field or break the server/agent switch.
 */

jest.mock('../../contexts/AuthContext', () => ({
  useAuth: () => ({
    user: {
      username: 'admin',
      is_admin: true,
      can_modify_servers: true,
      ui_permissions: {
        register_service: ['all'],
        publish_agent: ['all'],
      },
    },
  }),
}));
jest.mock('../../hooks/useDuplicateCheck', () => ({
  useDuplicateCheck: () => ({
    runCheck: jest.fn(),
    collisionWith: [],
    advisoryMatches: [],
    showModal: false,
    closeModal: jest.fn(),
    reset: jest.fn(),
  }),
}));
jest.mock('../../components/DuplicateCheckModal', () => {
  const M = () => null;
  M.displayName = 'DuplicateCheckModal';
  return M;
});

function renderPage() {
  return render(
    <MemoryRouter>
      <RegisterPage />
    </MemoryRouter>,
  );
}

describe('RegisterPage', () => {
  it('defaults to the server registration form with its core fields', () => {
    renderPage();
    expect(screen.getByText('Server Name *')).toBeInTheDocument();
    expect(screen.getByText('Path *')).toBeInTheDocument();
    expect(screen.getByText('Deployment Type *')).toBeInTheDocument();
  });

  it('switches to the agent form when the Agent tab is selected', () => {
    renderPage();
    // Click the Agent registration-type tab.
    fireEvent.click(screen.getByText('A2A Agent'));
    expect(screen.getByText('Agent Name *')).toBeInTheDocument();
  });

  it('auto-generates the server path from the name', () => {
    renderPage();
    const nameInput = screen.getByPlaceholderText(/My Custom Server|server name/i);
    fireEvent.change(nameInput, { target: { value: 'My Cool Server' } });
    // Path is auto-generated (slugified) when left untouched.
    expect(screen.getByDisplayValue(/my-cool-server/)).toBeInTheDocument();
  });

  it('offers Quick Form and JSON Upload registration modes', () => {
    renderPage();
    expect(screen.getByText('Quick Form')).toBeInTheDocument();
    expect(screen.getByText('JSON Upload')).toBeInTheDocument();
  });
});
