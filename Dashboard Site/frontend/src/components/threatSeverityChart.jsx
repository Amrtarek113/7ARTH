import React from 'react';
import { useTheme } from "@mui/material";
import { ResponsiveBar } from "@nivo/bar";
import { tokens } from "../theme";

const ThreatSeverityChart = ({ isDashboard = false, data }) => {
  const theme = useTheme();
  const colors = tokens(theme.palette.mode);

  if (!data || data.length === 0) {
    console.warn('No threat level data provided to ThreatSeverityChart');
    return <div>No data available for Threat Severity Chart</div>;
  }

  // Ensure all data items have severity and value
  const processedData = data.map(item => ({
    severity: item.severity || 'Unknown',
    value: item.value || 0,
  }));

  const customColors = {
    "Low": colors.greenAccent[500],
    "Medium": colors.yellowAccent[500],
    "High": colors.orangeAccent[500],
    "Critical": colors.redAccent[500],
    "Unknown": colors.grey[500], // Fallback color
  };

  return (
    <ResponsiveBar
      data={processedData}
      theme={{
        axis: {
          domain: { line: { stroke: colors.grey[100], strokeWidth: 2 } },
          legend: { text: { fill: colors.grey[100], fontSize: 14, fontWeight: 600 } },
          ticks: { line: { stroke: colors.grey[200], strokeWidth: 1 }, text: { fill: colors.grey[100], fontSize: 12 } },
        },
        legends: { text: { fill: colors.grey[100], fontSize: 12 } },
        grid: { line: { stroke: colors.grey[700], strokeWidth: 1, strokeDasharray: "4 4" } },
      }}
      keys={["value"]}
      indexBy="severity"
      margin={{ top: 50, right: 130, bottom: 90, left: 80 }}
      padding={0.6}
      valueScale={{ type: "linear", min: 0, max: "auto", nice: true }}
      indexScale={{ type: "band", round: true, padding: 0.2 }}
      colors={({ data }) => customColors[data.severity] || colors.grey[500]}
      borderColor={{ from: "color", modifiers: [["darker", 1.6]] }}
      axisTop={null}
      axisRight={null}
      axisBottom={{
        tickSize: 5,
        tickPadding: 10,
        tickRotation: 0,
        legend: isDashboard ? undefined : "Threat Severity",
        legendPosition: "middle",
        legendOffset: 60,
        text: { fill: colors.grey[100], fontSize: 12 },
      }}
      axisLeft={{
        tickSize: 5,
        tickPadding: 10,
        tickRotation: 0,
        legend: isDashboard ? undefined : "Count",
        legendPosition: "middle",
        legendOffset: -60,
        text: { fill: colors.grey[100], fontSize: 12 },
      }}
      enableGridX={true}
      enableGridY={true}
      enableLabel={true}
      label={d => d.value > 0 ? `${d.value}` : ''}
      labelSkipWidth={12}
      labelSkipHeight={12}
      labelTextColor={{ from: "color", modifiers: [["darker", 3]] }}
      legends={[
        {
          dataFrom: "keys",
          anchor: "bottom-right",
          direction: "column",
          justify: false,
          translateX: 120,
          translateY: 0,
          itemsSpacing: 5,
          itemWidth: 120,
          itemHeight: 20,
          itemDirection: "left-to-right",
          itemOpacity: 0.85,
          symbolSize: 15,
          symbolShape: "square",
          effects: [
            {
              on: "hover",
              style: {
                itemBackground: colors.primary[400],
                itemOpacity: 1,
              },
            },
          ],
        },
      ]}
      role="application"
      barAriaLabel={function (e) { return e.id + ": " + e.formattedValue + " incidents"; }}
      animate={true}
      motionConfig="gentle"
    />
  );
};

export default ThreatSeverityChart;