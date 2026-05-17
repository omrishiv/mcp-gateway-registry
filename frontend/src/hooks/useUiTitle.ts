import { useState, useEffect } from 'react';
import axios from 'axios';

const DEFAULT_UI_TITLE = 'AI Gateway & Registry';

interface VersionResponse {
  version: string;
  ui_title?: string;
}

let cachedTitle: string | null = null;

export function useUiTitle(): string {
  const [title, setTitle] = useState<string>(cachedTitle || DEFAULT_UI_TITLE);

  useEffect(() => {
    if (cachedTitle) return;

    axios
      .get<VersionResponse>('/api/version')
      .then((res) => {
        const t = res.data.ui_title || DEFAULT_UI_TITLE;
        cachedTitle = t;
        setTitle(t);
      })
      .catch((err) => {
        console.error('Failed to load ui_title from /api/version:', err);
        cachedTitle = DEFAULT_UI_TITLE;
      });
  }, []);

  return title;
}
