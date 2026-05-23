// mockDataRansomware.js
export const mockDataRansomware = [
    {
      id: 1,
      variant: "WannaCry",
      targetIp: "192.168.1.100",
      detectionDate: "2025-03-10",
      ransomAmount: 500,
      protocol: "SMB",
    },
    {
      id: 2,
      variant: "Ryuk",
      targetIp: "10.0.0.15",
      detectionDate: "2025-03-15",
      ransomAmount: 1000,
      protocol: "RDP",
    },
    {
      id: 3,
      variant: "Locky",
      targetIp: "172.16.254.1",
      detectionDate: "2025-03-20",
      ransomAmount: 300,
      protocol: "HTTP",
    },
    {
      id: 4,
      variant: "Cerber",
      targetIp: "192.168.0.50",
      detectionDate: "2025-03-25",
      ransomAmount: 700,
      protocol: "FTP",
    },
    {
      id: 5,
      variant: "Petya",
      targetIp: "10.10.10.10",
      detectionDate: "2025-04-01",
      ransomAmount: 1200,
      protocol: "SMB",
    },
  ];