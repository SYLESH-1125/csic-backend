const fs = require('fs');
let c = fs.readFileSync('c:/CISC/operation-room/frontend/src/components/tiptap/EvidenceBlockNode.tsx', 'utf8');

const matchStr = unction TimelineEventContent({ data, displayMode }: { data: any; displayMode: string }) {
  const { timestamp, event_type, source, message, severity, events } = data     

  // If we have multiple events, use the vertical chart;

const replaceStr = unction TimelineEventContent({ data, displayMode }: { data: any; displayMode: string }) {
  const { timestamp, event_type, source, message, severity, events } = data     
  const clusters = data.clusters || [];

  // If we have DBSCAN clusters, render them automatically
  if (clusters && clusters.length > 0) {
    return (
      <div className="p-4">
        <TimelineVerticalChart
          events={clusters.map((c: any) => ({
            id: String(c.cluster_id || Math.random()),
            timestamp: c.start || "N/A",
            event_type: "Density Cluster",
            severity: c.cluster_id === 'outliers' ? 'high' : 'info',
            source: "DBSCAN",
            actor: \Count: \\,
          }))}
          highlightAnchor={true}
          className={displayMode === 'compact' ? 'max-h-48' : 'max-h-80'}       
        />
        {displayMode === 'compact' && clusters.length > 5 && (
          <p className="text-xs text-muted-foreground text-center mt-2">        
            + {clusters.length - 5} more clusters
          </p>
        )}
      </div>
    )
  }

  // If we have multiple events, use the vertical chart;

c = c.replace(matchStr, replaceStr);
fs.writeFileSync('c:/CISC/operation-room/frontend/src/components/tiptap/EvidenceBlockNode.tsx', c);
