package autoTests;

import org.junit.Test;
import org.junit.After;

import auto.*;
import core.*;

public class GatewayTest {

	@Test
	public void testGateway() {
		   
		System.out.println("########## TESTS FOR GATEWAY ##########");
		   
		System.out.println("~~~~~ NO DEFENSES IN PLACE / ALL DEFENSES IN PLACE ~~~~~");
		
		Network network = new Network();
		Gateway gateway = new Gateway();
		IAMaccount iamacct = new IAMaccount();
		
		network.addTrafficGateways(gateway);
		iamacct.addNetworks(network);
		iamacct.addTrafficGateways(gateway);
		
		Attacker attacker = new Attacker();
		attacker.addAttackPoint(iamacct.compromise);
		attacker.addAttackPoint(network.denialOfService);
		attacker.attack();
		   
		iamacct.compromisedAccess.assertCompromisedInstantaneously();
		network.compromisedAccess.assertCompromisedInstantaneously();
		gateway.compromisedAccess.assertCompromisedInstantaneously();
		gateway.createNewConnections.assertCompromisedInstantaneously();
		network._access.assertCompromisedInstantaneously();
		gateway.denialOfService.assertCompromisedInstantaneously();
		network.denialOfService.assertCompromisedInstantaneously();
		   
	}		   
	
	@After
	public void deleteModel() {
		Asset.allAssets.clear();
		AttackStep.allAttackSteps.clear();
		Defense.allDefenses.clear();
	}


}


