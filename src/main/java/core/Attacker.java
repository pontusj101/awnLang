package core;

import java.util.HashSet;
import java.util.Set;

public class Attacker {

   protected Set<AttackStep> activeAttackSteps = new HashSet<>();

   public void addAttackPoint(AttackStep attackPoint) {
      attackPoint.ttc = 0;
      activeAttackSteps.add(attackPoint);
   }

   public void addRandomAttackPoint(long randomSeed) {
      AttackStep attackPoint = AttackStep.randomAttackStep(randomSeed);
      System.out.println("Attack point: " + attackPoint.fullName());
      addAttackPoint(attackPoint);
   }

   private AttackStep getShortestActiveStep() {
      AttackStep shortestStep = null;
      double shortestTtc = Double.MAX_VALUE;
      for (AttackStep attackStep : activeAttackSteps) {
         if (attackStep.ttc < shortestTtc) {
            shortestTtc = attackStep.ttc;
            shortestStep = attackStep;
         }
      }
      return shortestStep;
   }

   public void reset() {
      for (AttackStep attackStep : AttackStep.allAttackSteps) {
         attackStep.ttc = Double.MAX_VALUE;
      }
   }

   public void attack() {

      System.out.println("The model contains " + Integer.toString(Asset.allAssets.size()) + " assets and " + Integer.toString(AttackStep.allAttackSteps.size()) + " attack steps.");
      AttackStep currentAttackStep = null;

      for (AttackStep attackStep : AttackStep.allAttackSteps) {
         attackStep.setExpectedParents();
      }

      for (Defense defense : Defense.allDefenses) {
         if (!defense.isEnabled()) {
            addAttackPoint(defense.disable);
         }
      }

      while (!activeAttackSteps.isEmpty()) {
         currentAttackStep = getShortestActiveStep();
         currentAttackStep.updateChildren(activeAttackSteps);
         activeAttackSteps.remove(currentAttackStep);
      }
   }

}
