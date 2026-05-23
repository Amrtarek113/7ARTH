import React from 'react';
import { ResponsiveBar } from "@nivo/bar";
import { useTheme } from "@mui/material";
import { tokens } from "../theme";

const PortActivityChart = ({ isDashboard = false, data }) => {
  const theme = useTheme();
  const colors = tokens(theme.palette.mode);

  if (!data || data.length === 0) {
    console.warn('No port activity data provided to PortActivityChart');
    return <div>No data available for Port Activity Chart</div>;
  }

  return (
    <ResponsiveBar
      data={data}
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
      indexBy="port"
      margin={{ top: 50, right: 130, bottom: 90, left: 80 }}
      padding={0.6}
      valueScale={{ type: "linear", min: 0, max: "auto", nice: true }}
      indexScale={{ type: "band", round: true, padding: 0.2 }}
      colors={colors.blueAccent[500]}
      borderColor={{ from: "color", modifiers: [["darker", 1.6]] }}
      axisTop={null}
      axisRight={null}
      axisBottom={{
        tickSize: 5,
        tickPadding: 10,
        tickRotation: 45,
        legend: isDashboard ? undefined : "Port Number",
        legendPosition: "middle",
        legendOffset: 60,
        text: { fill: colors.grey[100], fontSize: 12 },
      }}
      axisLeft={{
        tickSize: 5,
        tickPadding: 10,
        tickRotation: 0,
        legend: isDashboard ? undefined : "Activity Count",
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
      role="application"
      barAriaLabel={function (e) { return e.id + ": " + e.formattedValue + " activities"; }}
      animate={true}
      motionConfig="gentle"
    />
  );
};

export default PortActivityChart;