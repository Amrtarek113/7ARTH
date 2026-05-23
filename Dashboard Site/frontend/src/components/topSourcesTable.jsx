import React from 'react';
import { Box, Typography, useTheme } from "@mui/material";
import { DataGrid } from '@mui/x-data-grid';
import { tokens } from "../theme";

const TopSourcesTable = ({ data }) => {
  const theme = useTheme();
  const colors = tokens(theme.palette.mode);

  if (!data || data.length === 0) {
    console.warn('No source IP data provided to TopSourcesTable');
    return <div>No data available for Top Sources Table</div>;
  }

  const columns = [
    { field: 'ip', headerName: 'Source IP', flex: 1, headerAlign: 'center', align: 'center' },
    { field: 'count', headerName: 'Incident Count', flex: 1, headerAlign: 'center', align: 'center' },
    { field: 'attack_types', headerName: 'Attack Types', flex: 1, headerAlign: 'center', align: 'center' },
  ];

  const rows = data.map((item, index) => ({
    id: index,
    ip: item.ip,
    count: item.count || 0,
    attack_types: Array.isArray(item.attack_types) ? item.attack_types.join(', ') : 'N/A',
  }));

  console.log('TopSourcesTable data:', rows);

  return (
    <Box
      sx={{
        height: '300px',
        width: '100%',
        '& .MuiDataGrid-root': {
          border: `1px solid ${colors.grey[700]}`,
          backgroundColor: colors.primary[400],
        },
        '& .MuiDataGrid-cell': {
          color: colors.grey[100],
        },
        '& .MuiDataGrid-columnHeaders': {
          backgroundColor: colors.blueAccent[700],
          color: colors.grey[100],
        },
      }}
    >
      <DataGrid
        rows={rows}
        columns={columns}
        pageSize={5}
        rowsPerPageOptions={[5]}
        disableSelectionOnClick
        autoHeight
      />
    </Box>
  );
};

export default TopSourcesTable;