/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{js,ts,jsx,tsx}"],
  theme: {
    extend: {
      colors: {
        noc: {
          bg: "#0b1220",
          panel: "#111827",
          border: "#1f2a3d",
          accent: "#22d3ee",
          good: "#22c55e",
          bad: "#ef4444",
          warn: "#f59e0b",
          muted: "#94a3b8",
        },
      },
      fontFamily: {
        sans: ['"IBM Plex Sans"', "Segoe UI", "system-ui", "sans-serif"],
        mono: ['"IBM Plex Mono"', "Consolas", "monospace"],
      },
      boxShadow: {
        panel: "0 0 0 1px rgba(34, 211, 238, 0.08), 0 12px 40px rgba(0,0,0,0.35)",
      },
    },
  },
  plugins: [],
};
