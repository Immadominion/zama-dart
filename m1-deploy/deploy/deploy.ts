import { DeployFunction } from "hardhat-deploy/types";
import { HardhatRuntimeEnvironment } from "hardhat/types";

const func: DeployFunction = async function (hre: HardhatRuntimeEnvironment) {
  const { deployer } = await hre.getNamedAccounts();
  const { deploy } = hre.deployments;

  // Public-decryptable counter (M1).
  const cc = await deploy("ConfidentialCounter", { from: deployer, log: true });
  console.log(`ConfidentialCounter contract: `, cc.address);

  // User-decryptable counter (M2): grants the running total to msg.sender.
  const fc = await deploy("FHECounter", { from: deployer, log: true });
  console.log(`FHECounter contract: `, fc.address);
};
export default func;
func.id = "deploy_counters";
func.tags = ["Counters"];
