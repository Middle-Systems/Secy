/**
 * Pure, non-JSX bits of asset-type display — split out of
 * `infrastructure.helpers.tsx` so that file can stay component-only (keeps
 * fast refresh happy).
 */
import { Container, Globe, Server, type LucideIcon } from 'lucide-react';

import type { AssetType } from '@/api/types';

/** Icon + human label per {@link AssetType}. */
export const ASSET_TYPE_STYLES: Record<AssetType, { icon: LucideIcon; label: string }> = {
  CONTAINER_IMAGE: { icon: Container, label: 'Container image' },
  HOST: { icon: Server, label: 'Host' },
  SERVICE: { icon: Globe, label: 'Service' },
};

export function assetTypeLabel(type: AssetType): string {
  return ASSET_TYPE_STYLES[type]?.label ?? type;
}
