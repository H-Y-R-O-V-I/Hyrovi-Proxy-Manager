import cn from "classnames";
import styles from "./HyroviBrand.module.css";

interface Props {
	className?: string;
	compact?: boolean;
}

export function HyroviBrand({ className, compact = false }: Props) {
	return (
		<div className={cn(styles.brand, compact && styles.compact, className)}>
			<span className={styles.mark} aria-hidden="true">H</span>
			<span className={styles.wordmark}>
				<strong>HYROVI</strong>
				{compact ? null : <small>Proxy Manager</small>}
			</span>
		</div>
	);
}
