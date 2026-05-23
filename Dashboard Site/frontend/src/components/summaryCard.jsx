import React from 'react';
import { Box, Typography, useTheme } from "@mui/material";
import { tokens } from "../theme";

const SummaryCard = ({ data }) => {
  const theme = useTheme();
  const colors = tokens(theme.palette.mode);

  if (!data) {
    console.warn('No data provided to SummaryCard');
    return <div>No data available for Summary Card</div>;
  }

  const totalThreats = Object.values(data.attack_counts || {}).reduce((sum, count) => sum + (count || 0), 0) - (data.attack_counts?.Normal || 0);

  console.log('SummaryCard data:', { totalThreats, totalPackets: data.total_packets });

  return (
    <Box
      sx={{
        backgroundColor: colors.primary[400],
        padding: '20px',
        borderRadius: '8px',
        display: 'flex',
        flexDirection: 'column',
        gap: '10px',
      }}
    >
      <Typography variant="h4" color={colors.grey[100]} fontWeight="bold">
        Analysis Summary
      </Typography>
      <Typography variant="h6" color={colors.greenAccent[500]}>
        Total Threats Detected: {totalThreats || 'N/A'}
      </Typography>
      <Typography variant="h6" color={colors.greenAccent[500]}>
        Total Packets Analyzed: {data.total_packets || 'N/A'}
      </Typography>
      <Typography variant="h6" color={colors.greenAccent[500]}>
        Analysis Timestamp: {data.timestamp || 'N/A'}
      </Typography>
    </Box>
  );
};

export default SummaryCard;