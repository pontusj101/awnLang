package autoTests;

import org.junit.Test;
import org.junit.After;

import auto.*;
import core.*;

public class MachineTest {

   @Test
   public void testMachine() {
	   
	   System.out.println("########## TESTS FOR MACHINE ##########");
	   
	   System.out.println("~~~~~ NO DEFENSES IN PLACE / ALL DEFENSES IN PLACE ~~~~~");
	   
	   Machine machine = new Machine();
	   
	   Attacker attacker = new Attacker();
	   attacker.addAttackPoint(machine.connect);
	   attacker.addAttackPoint(machine.authenticate);
	   attacker.attack();
	   
	   machine.authenticatedAccess.assertCompromisedInstantaneously();
	   machine.access.assertCompromisedInstantaneously();
	   machine._machineAccess.assertCompromisedInstantaneously();
	   machine.denialOfService.assertCompromisedInstantaneously();
	  
   }

	@After
	public void deleteModel() {
		Asset.allAssets.clear();
		AttackStep.allAttackSteps.clear();
		Defense.allDefenses.clear();
	}


}


