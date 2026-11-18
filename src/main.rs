mod evaluation_domain;
mod field;
mod polynomial;

use evaluation_domain::EvaluationDomain;
use field::FieldElement;
use polynomial::Polynomial;

fn main() {
    let p = 97;

    let fe = |value| FieldElement::new(value, p);

    // f(X) = 3 + 2X + 5X^2 + 4X^3 + 7X^4 + 6X^5
    let f = Polynomial::new(vec![fe(3), fe(2), fe(5), fe(4), fe(7), fe(6)]);

    // Multiplicative subgroup of size 32.
    // omega = 19 has exact order 32 in F_97.
    let domain = EvaluationDomain::new(fe(19), 32);

    // Evaluate f over the domain.
    let evaluations: Vec<FieldElement> = domain.points().iter().map(|x| f.evaluate(*x)).collect();

    // Folding challenge.
    let alpha = fe(7);

    // Fold the evaluation vector.
    let (folded_domain, folded_evaluations) = domain.fold_evaluations(&evaluations, alpha);

    println!("Original polynomial: {:?}", f);

    println!("Original domain size: {}", domain.size);

    println!("Original evaluations: {}", evaluations.len());

    println!("Folded domain size: {}", folded_domain.size);

    println!("Folded evaluations: {}", folded_evaluations.len());

    println!("New domain generator: {}", folded_domain.generator.value);

    println!("Folded polynomial: {:?}", f.fold(alpha));
}
