mod field;
mod polynomial;

use field::FieldElement;
use polynomial::Polynomial;

fn main() {
    let p = 97;

    // f(X) = 3 + 2X + 5X^2 + 4X^3
    let polynomial = Polynomial::new(vec![
        FieldElement::new(3, p),
        FieldElement::new(2, p),
        FieldElement::new(5, p),
        FieldElement::new(4, p),
    ]);

    let alpha = FieldElement::new(7, p);

    let folded = polynomial.fold(alpha);

    println!("Original polynomial: {:?}", polynomial);
    println!("Folded polynomial:   {:?}", folded);

    let x = FieldElement::new(2, p);
    let x_squared = x * x;

    println!("f(2)   = {:?}", polynomial.evaluate(x));
    println!("f(-2)  = {:?}", polynomial.evaluate(-x));
    println!("g(2^2) = {:?}", folded.evaluate(x_squared));
}
