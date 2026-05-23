// mockDataIoT.js
export const mockDataIoT = [
    {
      id: 1,
      src_ip: "192.168.1.10",
      dst_ip: "10.0.0.5",
      protocol: "TCP",
      flow_duration: 120.5, // in seconds
      attack_type: "Normal",
      timestamp: "2025-03-10 08:15:23",
    },
    {
      id: 2,
      src_ip: "172.16.0.20",
      dst_ip: "192.168.1.100",
      protocol: "UDP",
      flow_duration: 45.3,
      attack_type: "DDoS_Hping",
      timestamp: "2025-03-15 14:22:10",
    },
    {
      id: 3,
      src_ip: "10.10.10.15",
      dst_ip: "192.168.0.50",
      protocol: "TCP",
      flow_duration: 300.0,
      attack_type: "Brute_Force_SSH",
      timestamp: "2025-03-20 09:45:00",
    },
    {
      id: 4,
      src_ip: "192.168.1.25",
      dst_ip: "172.16.254.1",
      protocol: "UDP",
      flow_duration: 15.8,
      attack_type: "Slowloris",
      timestamp: "2025-03-25 16:30:45",
    },
    {
      id: 5,
      src_ip: "10.0.0.30",
      dst_ip: "192.168.1.200",
      protocol: "TCP",
      flow_duration: 90.2,
      attack_type: "Normal",
      timestamp: "2025-04-01 11:10:15",
    },
  ];