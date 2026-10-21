import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { getSecurityVisitors } from "src/api/backend/securityVisitors";
import SmartAnalyticsStudio from "./SmartAnalyticsStudio";
import SmartStudio from "./SmartStudio";

/**
 * First-class HYROVI Sec tab for the existing analytics collector.
 * This is independent of Users Studio and its navigation state.
 */
export default function SmartHub() {
  const [section, setSection] = useState<"analytics" | "security">("analytics");
  const security = useQuery({
    queryKey: ["security-visitors"],
    queryFn: getSecurityVisitors,
    enabled: section === "security",
    staleTime: 7000,
    refetchInterval: section === "security" ? 20000 : false,
    retry: false,
  });

  return section === "analytics" ?
    <SmartAnalyticsStudio onSecurity={() => setSection("security")} /> :
    <SmartStudio report={security.data?.automaticActivity?.smart}
      loading={security.isLoading} error={security.error}
      onRefresh={() => void security.refetch()}
      onBack={() => setSection("analytics")} />;
}
