package autoTests;

import org.junit.Test;
import org.junit.After;

import auto.*;
import core.*;

public class NetworkTest {

	@Test
	public void testNetwork() {
		   
		System.out.println("########## TESTS FOR NETWORK ##########");
		   
		System.out.println("~~~~~ NO DEFENSES IN PLACE / ALL DEFENSES IN PLACE ~~~~~");
		
		Network network = new Network();
		IAMaccount iamacct = new IAMaccount();
		
		iamacct.addNetworks(network);
		
		Attacker attacker = new Attacker();
		attacker.addAttackPoint(iamacct.compromise);
		attacker.addAttackPoint(network.denialOfService);
		attacker.attack();
		   
		iamacct.compromisedAccess.assertCompromisedInstantaneously();
		network.compromisedAccess.assertCompromisedInstantaneously();
		network._access.assertCompromisedInstantaneously();
		network.denialOfService.assertCompromisedInstantaneously();
		   
	}		   
	
	@After
	public void deleteModel() {
		Asset.allAssets.clear();
		AttackStep.allAttackSteps.clear();
		Defense.allDefenses.clear();
	}


}


