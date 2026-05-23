import React, { useState } from 'react';
import { Box, Button, Typography, useTheme, CircularProgress } from '@mui/material';
import Header from '../../components/Header';
import { tokens } from '../../theme';
import Topbar from '../global/Topbar';
import Sidebar from '../global/Sidebar';
import CloudUploadIcon from '@mui/icons-material/CloudUpload';
import { useNavigate } from 'react-router-dom';
import { uploadFile, analyzeFile } from '../../services/api';

const FileImport = () => {
  const theme = useTheme();
  const colors = tokens(theme.palette.mode);
  const navigate = useNavigate();
  const [selectedFile, setSelectedFile] = useState(null);
  const [error, setError] = useState(null);
  const [uploading, setUploading] = useState(false);
  const [analyzing, setAnalyzing] = useState(false);

  const handleFileChange = (event) => {
    const file = event.target.files[0];
    if (file && (file.name.endsWith('.csv') || file.name.endsWith('.pcap'))) {
      setSelectedFile(file);
      setError(null);
      console.log('Selected file:', file);
    } else {
      setSelectedFile(null);
      setError('Please select a .csv or .pcap file.');
      event.target.value = null;
    }
  };

  const handleUploadAndAnalyze = async () => {
    if (!selectedFile) return;

    const token = localStorage.getItem('token');
    if (!token) {
      setError('Please log in to upload files');
      navigate('/login');
      return;
    }

    setUploading(true);
    setError(null);

    try {
      // Step 1: Upload the file
      const uploadResponse = await uploadFile(selectedFile);
      if (uploadResponse.status !== 'success') {
        throw new Error(uploadResponse.message || 'File upload failed');
      }

      const filename = uploadResponse.filename;
      console.log('File uploaded successfully:', filename);

      // Step 2: Analyze the uploaded file
      setUploading(false);
      setAnalyzing(true);

      const analysisResponse = await analyzeFile(filename);
      if (analysisResponse.status === 'success') {
        console.log('File analysis successful:', analysisResponse.data);
        navigate('/AnalysisResults', { state: { analysisData: analysisResponse.data } });
      } else {
        throw new Error(analysisResponse.message || 'File analysis failed');
      }
    } catch (err) {
      console.error('Error:', err);
      if (err.response?.status === 401) {
        localStorage.removeItem('token');
        setError('Session expired. Please log in again.');
        navigate('/login');
      } else {
        setError(err.response?.data?.message || err.message || 'Error processing file');
      }
    } finally {
      setUploading(false);
      setAnalyzing(false);
    }
  };

  return (
    <Box display="flex" minHeight="100vh">
      {/* <Sidebar /> */}
      <Box
        sx={{
          flexGrow: 1,
          display: 'flex',
          flexDirection: 'column',
        }}
      >
        {/* <Topbar /> */}
        <Box
          sx={{
            padding: '20px',
            boxSizing: 'border-box',
            flexGrow: 1,
          }}
        >
          <Header title="FILE IMPORT" subtitle="Upload CSV or PCAP files for analysis" />
          {error && (
            <Typography variant="body1" color={colors.redAccent[500]} mb={2} textAlign="center">
              {error}
            </Typography>
          )}
          <Box
            display="flex"
            flexDirection="column"
            alignItems="center"
            justifyContent="center"
            backgroundColor={colors.primary[400]}
            borderRadius="3px"
            p={4}
            mt={4}
            sx={{ height: '400px' }}
          >
            <CloudUploadIcon sx={{ fontSize: 60, color: colors.grey[100], mb: 2 }} />
            <Typography variant="h5" color={colors.grey[100]} mb={2}>
              Drag and drop or click to upload CSV/PCAP files
            </Typography>
            <input
              type="file"
              accept=".csv,.pcap"
              onChange={handleFileChange}
              style={{ display: 'none' }}
              id="file-upload"
            />
            <label htmlFor="file-upload">
              <Button
                variant="contained"
                component="span"
                sx={{
                  backgroundColor: colors.blueAccent[700],
                  color: colors.grey[100],
                  padding: '10px 20px',
                  borderRadius: '3px',
                  '&:hover': {
                    backgroundColor: colors.blueAccent[800],
                  },
                }}
              >
                Select File
              </Button>
            </label>
            {selectedFile && (
              <Typography variant="body1" color={colors.grey[100]} mt={2}>
                Selected: {selectedFile.name}
              </Typography>
            )}
            <Button
              variant="contained"
              disabled={!selectedFile || uploading || analyzing}
              onClick={handleUploadAndAnalyze}
              sx={{
                mt: 2,
                backgroundColor: colors.greenAccent[600],
                color: colors.grey[100],
                padding: '10px 20px',
                borderRadius: '3px',
                '&:hover': {
                  backgroundColor: colors.greenAccent[700],
                },
                '&:disabled': {
                  backgroundColor: colors.grey[600],
                },
              }}
            >
              {uploading ? (
                <>
                  <CircularProgress size={20} sx={{ mr: 1 }} />
                  Uploading...
                </>
              ) : analyzing ? (
                <>
                  <CircularProgress size={20} sx={{ mr: 1 }} />
                  Analyzing...
                </>
              ) : (
                'Upload and Analyze'
              )}
            </Button>
          </Box>
        </Box>
      </Box>
    </Box>
  );
};

export default FileImport;
