type Theme = 'dark' | 'light';

const stored = (localStorage.getItem('sigil-theme') as Theme | null) ?? 'dark';
export const theme = $state<{ value: Theme }>({ value: stored });

export function applyTheme(): void {
  document.documentElement.dataset.theme = theme.value;
}

export function toggleTheme(): void {
  theme.value = theme.value === 'dark' ? 'light' : 'dark';
  localStorage.setItem('sigil-theme', theme.value);
  applyTheme();
}

applyTheme();
