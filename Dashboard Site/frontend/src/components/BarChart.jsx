import { useTheme } from "@mui/material";
import { ResponsiveBar } from "@nivo/bar";
import { tokens } from "../theme";

const BarChart = ({ isDashboard = false, metrics }) => {
  const theme = useTheme();
  const colors = tokens(theme.palette.mode);

  if (!metrics) {
    console.warn('No metrics provided to BarChart');
    return <div>No data available for Bar Chart</div>;
  }

  const data = [
    { index: "Malicious URLs", value: Math.max(0, metrics.malicious_urls.current) },
    { index: "IoT Attacks", value: Math.max(0, metrics.iot_attacks.current) },
    { index: "Ransomware", value: Math.max(0, metrics.ransomware_incidents.current) },
  ];
  console.log('BarChart data:', data);

  const customColors = {
    "Malicious URLs": "#FF6384",
    "IoT Attacks": "#FF9F40",
    "Ransomware": "#9966FF",
  };

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
      indexBy="index"
      margin={{ top: 50, right: 130, bottom: 90, left: 80 }}
      padding={0.6}
      valueScale={{ type: "linear", min: 0, max: "auto", nice: true }}
      indexScale={{ type: "band", round: true, padding: 0.2 }}
      colors={({ id, data }) => customColors[data.index]}
      defs={[
        {
          id: "gradientA",
          type: "linearGradient",
          colors: [
            { offset: 0, color: "inherit", opacity: 0.7 },
            { offset: 100, color: "inherit", opacity: 0.3 },
          ],
        },
      ]}
      fill={[{ match: "*", id: "gradientA" }]}
      borderColor={{ from: "color", modifiers: [["darker", 1.6]] }}
      axisTop={null}
      axisRight={null}
      axisBottom={{
        tickSize: 5,
        tickPadding: 10,
        tickRotation: 0,
        legend: isDashboard ? undefined : "Threat Types",
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
      label={d => `${d.value}`}
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
      barAriaLabel={function (e) { return e.id + ": " + e.formattedValue + " threats"; }}
    />
  );
};

export default BarChart;