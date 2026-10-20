import { ReactQueryDevtools } from "@tanstack/react-query-devtools";

// Local development only; App.tsx excludes this module from production.
export default function DevelopmentQueryTools() {
	return <ReactQueryDevtools buttonPosition="bottom-right" position="right" />;
}
