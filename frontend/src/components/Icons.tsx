import type { SVGProps } from "react";

type IconProps = SVGProps<SVGSVGElement>;

const base = (props: IconProps) => ({
  width: 20,
  height: 20,
  viewBox: "0 0 24 24",
  fill: "none",
  stroke: "currentColor",
  strokeWidth: 1.7,
  strokeLinecap: "round" as const,
  strokeLinejoin: "round" as const,
  ...props,
});

export const ShieldIcon = (props: IconProps) => (
  <svg {...base(props)}>
    <path d="M12 3 5 6v6c0 4.5 3 7.6 7 9 4-1.4 7-4.5 7-9V6l-7-3Z" />
    <path d="m9 12 2 2 4-4" />
  </svg>
);

export const RadarIcon = (props: IconProps) => (
  <svg {...base(props)}>
    <circle cx="12" cy="12" r="9" />
    <circle cx="12" cy="12" r="5" />
    <path d="M12 12 18 6" />
    <circle cx="12" cy="12" r="1" fill="currentColor" stroke="none" />
  </svg>
);

export const HistoryIcon = (props: IconProps) => (
  <svg {...base(props)}>
    <path d="M3 12a9 9 0 1 0 3-6.7" />
    <path d="M3 4v5h5" />
    <path d="M12 8v4l3 2" />
  </svg>
);

export const PlusIcon = (props: IconProps) => (
  <svg {...base(props)}>
    <path d="M12 5v14M5 12h14" />
  </svg>
);

export const PlayIcon = (props: IconProps) => (
  <svg {...base(props)}>
    <path d="M7 4.5 19 12 7 19.5Z" />
  </svg>
);

export const StopIcon = (props: IconProps) => (
  <svg {...base(props)}>
    <rect x="6" y="6" width="12" height="12" rx="2" />
  </svg>
);

export const DownloadIcon = (props: IconProps) => (
  <svg {...base(props)}>
    <path d="M12 4v11" />
    <path d="m7 10 5 5 5-5" />
    <path d="M5 20h14" />
  </svg>
);

export const ChevronIcon = (props: IconProps) => (
  <svg {...base(props)}>
    <path d="m9 6 6 6-6 6" />
  </svg>
);

export const AlertIcon = (props: IconProps) => (
  <svg {...base(props)}>
    <path d="M12 4 3 20h18L12 4Z" />
    <path d="M12 10v4" />
    <circle cx="12" cy="17.2" r=".8" fill="currentColor" stroke="none" />
  </svg>
);

export const CheckIcon = (props: IconProps) => (
  <svg {...base(props)}>
    <path d="m5 12 4.5 4.5L19 7" />
  </svg>
);

export const TrashIcon = (props: IconProps) => (
  <svg {...base(props)}>
    <path d="M4 7h16M9 7V5h6v2M6 7l1 13h10l1-13" />
  </svg>
);

export const SearchIcon = (props: IconProps) => (
  <svg {...base(props)}>
    <circle cx="11" cy="11" r="6" />
    <path d="m16 16 4 4" />
  </svg>
);

export const LinkIcon = (props: IconProps) => (
  <svg {...base(props)}>
    <path d="M10 14a4 4 0 0 0 5.7 0l3-3a4 4 0 0 0-5.7-5.7l-1.5 1.5" />
    <path d="M14 10a4 4 0 0 0-5.7 0l-3 3a4 4 0 0 0 5.7 5.7l1.5-1.5" />
  </svg>
);

export const CodeIcon = (props: IconProps) => (
  <svg {...base(props)}>
    <path d="m8 8-4 4 4 4M16 8l4 4-4 4" />
  </svg>
);

export const ServerIcon = (props: IconProps) => (
  <svg {...base(props)}>
    <rect x="3" y="4" width="18" height="7" rx="2" />
    <rect x="3" y="13" width="18" height="7" rx="2" />
    <path d="M7 7.5h.01M7 16.5h.01" />
  </svg>
);

export const RefreshIcon = (props: IconProps) => (
  <svg {...base(props)}>
    <path d="M20 12a8 8 0 1 1-2.3-5.6" />
    <path d="M20 4v5h-5" />
  </svg>
);

export const CopyIcon = (props: IconProps) => (
  <svg {...base(props)}>
    <rect x="9" y="9" width="11" height="11" rx="2" />
    <path d="M15 9V6a2 2 0 0 0-2-2H6a2 2 0 0 0-2 2v7a2 2 0 0 0 2 2h3" />
  </svg>
);

export const DiffIcon = (props: IconProps) => (
  <svg {...base(props)}>
    <path d="M7 4v16M17 4v16" />
    <path d="M4 8h6M4 16h6M14 12h6" />
  </svg>
);

