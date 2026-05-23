import React from 'react';
import { ResponsiveLine } from "@nivo/line";
import { useTheme } from "@mui/material";
import { tokens } from "../theme";

const IncidentTimeline = ({ isDashboard = false, data }) => {
  const theme = useTheme();
  const colors = tokens(theme.palette.mode);

  if (!data || data.length === 0) {
    console.warn('No incident timeline data provided to IncidentTimeline');
    return <div>No data available for Incident Timeline</div>;
  }

  const processedData = [{
    id: "Incidents",
    color: colors.blueAccent[500],
    data: data.map((point, index) => ({
      x: new Date(point.timestamp || Date.now()).toLocaleTimeString(),
      y: point.count || 0,
    })),
  }];

  console.log('IncidentTimeline data:', processedData);

  return (
    <ResponsiveLine
      data={processedData}
      theme={{
        axis: { domain: { line: { stroke: colors.grey[100] } }, legend: { text: { fill: colors.grey[100] } }, ticks: { line: { stroke: colors.grey[100], strokeWidth: 1 }, text: { fill: colors.grey[100] } } },
        legends: { text: { fill: colors.grey[100] } },
        tooltip: { container: { color: colors.primary[500] } },
      }}
      colors={{ datum: "color" }}
      margin={{ top: 50, right: 110, bottom: 50, left: 60 }}
      xScale={{ type: "point" }}
      yScale={{ type: "linear", min: 0, max: "auto", stacked: false, reverse: false }}
      yFormat=" >-.2f"
      curve="catmullRom"
      axisTop={null}
      axisRight={null}
      axisBottom={{
        orient: "bottom",
        tickSize: 0,
        tickPadding: 5,
        tickRotation: 45,
        legend: isDashboard ? undefined : "Time",
        legendOffset: 36,
        legendPosition: "middle",
      }}
      axisLeft={{
        orient: "left",
        tickValues: 5,
        tickSize: 3,
        tickPadding: 5,
        tickRotation: 0,
        legend: isDashboard ? undefined : "Incident Count",
        legendOffset: -40,
        legendPosition: "middle",
      }}
      enableGridX={false}
      enableGridY={true}
      pointSize={8}
      pointColor={{ theme: "background" }}
      pointBorderWidth={2}
      pointBorderColor={{ from: "serieColor" }}
      pointLabelYOffset={-12}
      useMesh={true}
      legends={[
        {
          anchor: "bottom-right",
          direction: "column",
          justify: false,
          translateX: 100,
          translateY: 0,
          itemsSpacing: 0,
          itemDirection: "left-to-right",
          itemWidth: 80,
          itemHeight: 20,
          itemOpacity: 0.75,
          symbolSize: 12,
          symbolShape: "circle",
          symbolBorderColor: "rgba(0, 0, 0, .5)",
          effects: [{ on: "hover", style: { itemBackground: "rgba(0, 0, 0, .03)", itemOpacity: 1 } }],
        },
      ]}
    />
  );
};
export default IncidentTimeline;