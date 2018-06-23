package autoTests;

import org.junit.Test;
import org.junit.After;

import auto.*;
import core.*;

public class SecurityGroupTest {

	@Test
	public void testSecurityGroup() {
		   
		System.out.println("########## TESTS FOR SECURITY GROUP ##########");
		   
		System.out.println("~~~~~ NO DEFENSES IN PLACE / ALL DEFENSES IN PLACE ~~~~~");
		
		Dataflow dataflow = new Dataflow();
		SecurityGroup secGrp = new SecurityGroup();
		IAMaccount iamacct = new IAMaccount();
		
		iamacct.addSecurityGroup(secGrp);
		secGrp.addDataflows(dataflow);
		
		Attacker attacker = new Attacker();
		attacker.addAttackPoint(iamacct.compromise);
		attacker.attack();
		
		iamacct.compromisedAccess.assertCompromisedInstantaneously();
		secGrp.compromisedAccess.assertCompromisedInstantaneously();
		dataflow.request.assertCompromisedInstantaneously();
		dataflow.respond.assertCompromisedInstantaneously();
		dataflow.denialOfService.assertCompromisedInstantaneously();
		   
	}		   
	
	@After
	public void deleteModel() {
		Asset.allAssets.clear();
		AttackStep.allAttackSteps.clear();
		Defense.allDefenses.clear();
	}


}


