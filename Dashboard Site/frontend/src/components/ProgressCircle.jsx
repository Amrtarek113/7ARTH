import { Box, useTheme } from "@mui/material";
import { tokens } from "../theme";

const ProgressCircle = ({ value = 0, size = "40" }) => {
  const theme = useTheme();
  const colors = tokens(theme.palette.mode);
  
  // Normalize value to 0–1 range, assuming input may exceed 1
  const progress = Math.min(Math.max(value, 0), 1); // Clamp between 0 and 1
  const angle = progress * 360;

  console.log('ProgressCircle value:', value, 'normalized progress:', progress);

  return (
    <Box
      sx={{
        background: `radial-gradient(${colors.primary[400]} 55%, transparent 56%),
            conic-gradient(transparent 0deg ${angle}deg, ${colors.blueAccent[500]} ${angle}deg 360deg),
            ${colors.greenAccent[500]}`,
        borderRadius: "50%",
        width: `${size}px`,
        height: `${size}px`,
      }}
    />
  );
};
export default ProgressCircle;