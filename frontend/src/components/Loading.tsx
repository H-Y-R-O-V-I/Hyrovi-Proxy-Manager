import type { ReactNode } from "react";
import { T } from "src/locale";
import { HyroviBrand } from "./HyroviBrand";

interface Props {
	label?: string | ReactNode;
	noLogo?: boolean;
}
export function Loading({ label, noLogo }: Props) {
	return (
		<div className="empty text-center">
			{noLogo ? null : (
				<div className="mb-3">
					<HyroviBrand />
				</div>
			)}
			<div className="text-secondary mb-3">{label || <T id="loading" />}</div>
			<div className="progress progress-sm">
				<div className="progress-bar progress-bar-indeterminate" />
			</div>
		</div>
	);
}
