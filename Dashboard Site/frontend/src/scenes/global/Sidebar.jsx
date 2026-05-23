import { useState } from "react";
import { ProSidebar, Menu, MenuItem } from "react-pro-sidebar";
import { Box, IconButton, Typography, useTheme } from "@mui/material";
import { Link } from "react-router-dom";
import "react-pro-sidebar/dist/css/styles.css";
import { tokens } from "../../theme";
import HomeOutlinedIcon from "@mui/icons-material/HomeOutlined";
import BarChartOutlinedIcon from "@mui/icons-material/BarChartOutlined";
import PieChartOutlineOutlinedIcon from "@mui/icons-material/PieChartOutlineOutlined";
import TimelineOutlinedIcon from "@mui/icons-material/TimelineOutlined";
import MenuOutlinedIcon from "@mui/icons-material/MenuOutlined";
import MapOutlinedIcon from "@mui/icons-material/MapOutlined";
import SecurityOutlinedIcon from "@mui/icons-material/SecurityOutlined"; // Icon for URL
import LockOutlinedIcon from "@mui/icons-material/LockOutlined"; // Icon for Ransomware
import DevicesOutlinedIcon from "@mui/icons-material/DevicesOutlined"; // Icon for IoT

const Item = ({ title, to, icon, selected, setSelected }) => {
  const theme = useTheme();
  const colors = tokens(theme.palette.mode);
  return (
    <MenuItem
      active={selected === title}
      style={{
        color: colors.grey[100],
      }}
      onClick={() => setSelected(title)}
      icon={icon}
    >
      <Typography>{title}</Typography>
      <Link to={to} />
    </MenuItem>
  );
};

const Sidebar = () => {
  const theme = useTheme();
  const colors = tokens(theme.palette.mode);
  const [isCollapsed, setIsCollapsed] = useState(false);
  const [selected, setSelected] = useState("Dashboard");

  return (
    <Box
      sx={{
        position: "fixed",
        top: 0,
        left: 0,
        height: "100vh",
        zIndex: 1000,
        width: isCollapsed ? "80px" : "250px",
        "& .pro-sidebar-inner": {
          background: `${colors.primary[400]} !important`,
          height: "100%",
        },
        "& .pro-icon-wrapper": {
          backgroundColor: "transparent !important",
        },
        "& .pro-inner-item": {
          padding: "5px 35px 5px 20px !important",
        },
        "& .pro-inner-item:hover": {
          color: "#868dfb !important",
        },
        "& .pro-menu-item.active": {
          color: "#6870fa !important",
        },
      }}
    >
      <ProSidebar collapsed={isCollapsed}>
        <Menu iconShape="square">
          {/* LOGO AND MENU ICON */}
          <MenuItem
            onClick={() => setIsCollapsed(!isCollapsed)}
            icon={isCollapsed ? <MenuOutlinedIcon /> : undefined}
            style={{
              margin: "10px 0 20px 0",
              color: colors.grey[100],
            }}
          >
            {!isCollapsed && (
              <Box
                display="flex"
                justifyContent="space-between"
                alignItems="center"
                ml="15px"
              >
                <Typography variant="h3" color={colors.grey[100]}>
                  7arth
                </Typography>
                <IconButton onClick={() => setIsCollapsed(!isCollapsed)}>
                  <MenuOutlinedIcon />
                </IconButton>
              </Box>
            )}
          </MenuItem>

          {!isCollapsed && (
            <Box mb="25px">
              <Box display="flex" justifyContent="center" alignItems="center">
              </Box>
              <Box textAlign="center">
                <Typography
                  variant="h2"
                  color={colors.grey[100]}
                  fontWeight="bold"
                  sx={{ m: "10px 0 0 0" }}
                >
                  7arth
                </Typography>
                <Typography variant="h5" color={colors.greenAccent[500]}>
                  Security System
                </Typography>
              </Box>
            </Box>
          )}

          <Box
            paddingLeft={isCollapsed ? undefined : "10%"}
            sx={{
              overflowY: "auto",
              maxHeight: isCollapsed
                ? "calc(100vh - 60px)"
                : "calc(100vh - 260px)",
            }}
          >
            <Item
              title="Dashboard"
              to="/"
              icon={<HomeOutlinedIcon />}
              selected={selected}
              setSelected={setSelected}
            />

            <Typography
              variant="h6"
              color={colors.grey[300]}
              sx={{ m: "15px 0 5px 20px" }}
            >
              Security
            </Typography>
            <Item
              title="Attacker Detection"
              to="/attacker_detection"
              icon={<SecurityOutlinedIcon />}
              selected={selected}
              setSelected={setSelected}
            />
            <Item
              title="Normal"
              to="/normal"
              icon={<LockOutlinedIcon />}
              selected={selected}
              setSelected={setSelected}
            />
            <Item
              title="URL Monitoring"
              to="/url"
              icon={<SecurityOutlinedIcon />}
              selected={selected}
              setSelected={setSelected}
            />
            <Item
              title="Backdoor"
              to="/backdoors"
              icon={<LockOutlinedIcon />}
              selected={selected}
              setSelected={setSelected}
            />
            <Item
              title="Reconnaissance"
              to="/reconnaissance"
              icon={<LockOutlinedIcon />}
              selected={selected}
              setSelected={setSelected}
            />
            <Item
              title="ShellCode"
              to="/shellcode"
              icon={<LockOutlinedIcon />}
              selected={selected}
              setSelected={setSelected}
            />
            <Item
              title="Ransomware"
              to="/ransomware"
              icon={<LockOutlinedIcon />}
              selected={selected}
              setSelected={setSelected}
            />
            <Item
              title="IoT Traffic"
              to="/iot"
              icon={<DevicesOutlinedIcon />}
              selected={selected}
              setSelected={setSelected}
            />
            <Item
              title="DoS Detection"
              to="/dos"
              icon={<SecurityOutlinedIcon />}
              selected={selected}
              setSelected={setSelected}
            />
            <Item
              title="Exploits Detection"
              to="/exploits"
              icon={<LockOutlinedIcon />}
              selected={selected}
              setSelected={setSelected}
            />
            <Item
              title="Generic Attack Detection"
              to="/generic"
              icon={<SecurityOutlinedIcon />}
              selected={selected}
              setSelected={setSelected}
            />
            <Item
              title="Analysis Detection"
              to="/analysis"
              icon={<SecurityOutlinedIcon />}
              selected={selected}
              setSelected={setSelected}
            />
            <Item
              title="Worms Detection"
              to="/worms"
              icon={<LockOutlinedIcon />}
              selected={selected}
              setSelected={setSelected}
            />
          </Box>
        </Menu>
      </ProSidebar>
    </Box>
  );
};
export default Sidebar;
