export type ImageClassification = {
  status: 'unknown' | 'not-distroless' | 'distroless-consistent';
  summary: string; digest?: string; platform: string; architecture?: string; osPackages: number;
  tools: { name: string; version: string; kind: string }[]; limitations: string;
};

type ClassifiedScan = { image: string; status: string; startedAt: string; classification?: ImageClassification };

// A mutable-tag scan must never classify a different observed/pinned digest.
export function imageScanFor<T extends ClassifiedScan>(reference: string, scans: T[]): T | undefined {
  const digest = reference.includes('@sha256:') ? reference.split('@').at(-1) : '';
  return scans.filter(scan => scan.status === 'complete' && scan.classification && (digest
    ? scan.classification.digest?.split('@').at(-1) === digest
    : scan.image === reference)).sort((a, b) => b.startedAt.localeCompare(a.startedAt))[0];
}
