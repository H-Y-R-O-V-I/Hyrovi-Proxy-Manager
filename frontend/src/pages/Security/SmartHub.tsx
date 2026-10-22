import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { getSecurityVisitors } from "src/api/backend/securityVisitors";
import SmartAnalyticsStudio from "./SmartAnalyticsStudio";
import SmartHostsStudio from "./SmartHostsStudio";
import SmartStudio from "./SmartStudio";

/**
 * First-class HYROVI Sec tab for the existing analytics collector.
 * This is independent of Users Studio and its navigation state.
 */
export default function SmartHub() {
  const [section, setSection] = useState<"hosts" | "lab" | "security">("hosts");
  const security = useQuery({
    queryKey: ["security-visitors"],
    queryFn: getSecurityVisitors,
    enabled: section === "security",
    staleTime: 7000,
    refetchInterval: section === "security" ? 20000 : false,
    retry: false,
  });

  return <div>
    <div className="d-flex gap-2 flex-wrap mb-3" role="group" aria-label="HYROVI Smart Bereiche">
      <button type="button" className={"btn "+(section==="hosts"?"btn-primary":"btn-outline-secondary")}
        onClick={()=>setSection("hosts")}>Hosts & Analytics</button>
      <button type="button" className={"btn "+(section==="lab"?"btn-primary":"btn-outline-secondary")}
        onClick={()=>setSection("lab")}>Testlabor</button>
      <button type="button" className={"btn "+(section==="security"?"btn-primary":"btn-outline-secondary")}
        onClick={()=>setSection("security")}>Sicherheitsanalyse</button>
    </div>
    {section==="hosts"&&<SmartHostsStudio/>}
    {section==="lab"&&<SmartAnalyticsStudio onSecurity={()=>setSection("security")}/>}
    {section==="security"&&<SmartStudio report={security.data?.automaticActivity?.smart}
      loading={security.isLoading} error={security.error}
      onRefresh={() => void security.refetch()}
      onBack={() => setSection("hosts")} />}
  </div>;
}
