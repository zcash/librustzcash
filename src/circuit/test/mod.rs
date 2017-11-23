use pairing::{
    Engine,
    Field
};

use bellman::{
    LinearCombination,
    SynthesisError,
    ConstraintSystem
};

use std::collections::HashMap;

#[derive(Debug, Copy, Clone)]
pub enum Variable {
    Input(usize),
    Aux(usize)
}

#[derive(Debug)]
enum NamedObject {
    Constraint(usize),
    Var(Variable),
    Namespace
}

/// Constraint system for testing purposes.
pub struct TestConstraintSystem<E: Engine> {
    named_objects: HashMap<String, NamedObject>,
    current_namespace: Vec<String>,
    constraints: Vec<(LinearCombination<Variable, E>, LinearCombination<Variable, E>, LinearCombination<Variable, E>, String)>,
    inputs: Vec<(E::Fr, String)>,
    aux: Vec<(E::Fr, String)>
}

fn eval_lc<E: Engine>(
    terms: &[(Variable, E::Fr)],
    inputs: &[(E::Fr, String)],
    aux: &[(E::Fr, String)]
) -> E::Fr
{
    let mut acc = E::Fr::zero();

    for &(var, ref coeff) in terms {
        let mut tmp = match var {
            Variable::Input(index) => inputs[index].0,
            Variable::Aux(index) => aux[index].0
        };

        tmp.mul_assign(&coeff);
        acc.add_assign(&tmp);
    }

    acc
}

impl<E: Engine> TestConstraintSystem<E> {
    pub fn new() -> TestConstraintSystem<E> {
        let mut map = HashMap::new();
        map.insert("ONE".into(), NamedObject::Var(Variable::Input(0)));

        TestConstraintSystem {
            named_objects: map,
            current_namespace: vec![],
            constraints: vec![],
            inputs: vec![(E::Fr::one(), "ONE".into())],
            aux: vec![]
        }
    }

    pub fn which_is_unsatisfied(&self) -> Option<&str> {
        for &(ref a, ref b, ref c, ref path) in &self.constraints {
            let mut a = eval_lc::<E>(a.as_ref(), &self.inputs, &self.aux);
            let b = eval_lc::<E>(b.as_ref(), &self.inputs, &self.aux);
            let c = eval_lc::<E>(c.as_ref(), &self.inputs, &self.aux);

            a.mul_assign(&b);

            if a != c {
                return Some(&*path)
            }
        }

        None
    }

    pub fn is_satisfied(&self) -> bool
    {
        self.which_is_unsatisfied().is_none()
    }

    pub fn num_constraints(&self) -> usize
    {
        self.constraints.len()
    }

    pub fn set(&mut self, path: &str, to: E::Fr)
    {
        match self.named_objects.get(path) {
            Some(&NamedObject::Var(Variable::Input(index))) => self.inputs[index].0 = to,
            Some(&NamedObject::Var(Variable::Aux(index))) => self.aux[index].0 = to,
            Some(e) => panic!("tried to set path `{}` to value, but `{:?}` already exists there.", path, e),
            _ => panic!("no variable exists at path: {}", path)
        }
    }

    pub fn get(&mut self, path: &str) -> E::Fr
    {
        match self.named_objects.get(path) {
            Some(&NamedObject::Var(Variable::Input(index))) => self.inputs[index].0,
            Some(&NamedObject::Var(Variable::Aux(index))) => self.aux[index].0,
            Some(e) => panic!("tried to get value of path `{}`, but `{:?}` exists there (not a variable)", path, e),
            _ => panic!("no variable exists at path: {}", path)
        }
    }

    fn set_named_obj(&mut self, path: String, to: NamedObject) {
        if self.named_objects.contains_key(&path) {
            panic!("tried to create object at existing path: {}", path);
        }

        self.named_objects.insert(path, to);
    }
}

fn compute_path(ns: &[String], this: String) -> String {
    if this.chars().any(|a| a == '/') {
        panic!("'/' is not allowed in names");
    }

    let mut name = String::new();

    let mut needs_separation = false;
    for ns in ns.iter().chain(Some(&this).into_iter())
    {
        if needs_separation {
            name += "/";
        }

        name += ns;
        needs_separation = true;
    }

    name
}

impl<E: Engine> ConstraintSystem<E> for TestConstraintSystem<E> {
    type Variable = Variable;
    type Root = Self;

    fn one(&self) -> Self::Variable {
        Variable::Input(0)
    }

    fn alloc<F, A, AR>(
        &mut self,
        annotation: A,
        f: F
    ) -> Result<Self::Variable, SynthesisError>
        where F: FnOnce() -> Result<E::Fr, SynthesisError>, A: FnOnce() -> AR, AR: Into<String>
    {
        let index = self.aux.len();
        let path = compute_path(&self.current_namespace, annotation().into());
        self.aux.push((f()?, path.clone()));
        let var = Variable::Aux(index);
        self.set_named_obj(path, NamedObject::Var(var));

        Ok(var)
    }

    fn enforce<A, AR>(
        &mut self,
        annotation: A,
        a: LinearCombination<Self::Variable, E>,
        b: LinearCombination<Self::Variable, E>,
        c: LinearCombination<Self::Variable, E>
    )
        where A: FnOnce() -> AR, AR: Into<String>
    {
        let path = compute_path(&self.current_namespace, annotation().into());
        let index = self.constraints.len();
        self.set_named_obj(path.clone(), NamedObject::Constraint(index));

        self.constraints.push((a, b, c, path));
    }

    fn push_namespace<NR, N>(&mut self, name_fn: N)
    where NR: Into<String>, N: FnOnce() -> NR
    {
        let name = name_fn().into();
        let path = compute_path(&self.current_namespace, name.clone());
        self.set_named_obj(path.clone(), NamedObject::Namespace);
        self.current_namespace.push(name);
    }

    fn pop_namespace(&mut self)
    {
        assert!(self.current_namespace.pop().is_some());
    }

    fn get_root(&mut self) -> &mut Self::Root
    {
        self
    }
}

#[test]
fn test_cs() {
    use pairing::bls12_381::{Bls12, Fr};
    use pairing::PrimeField;

    let mut cs = TestConstraintSystem::<Bls12>::new();
    assert!(cs.is_satisfied());
    assert_eq!(cs.num_constraints(), 0);
    let a = cs.namespace(|| "a").alloc(|| "var", || Ok(Fr::from_str("10").unwrap())).unwrap();
    let b = cs.namespace(|| "b").alloc(|| "var", || Ok(Fr::from_str("4").unwrap())).unwrap();
    let c = cs.alloc(|| "product", || Ok(Fr::from_str("40").unwrap())).unwrap();

    cs.enforce(
        || "mult",
        LinearCombination::zero() + a,
        LinearCombination::zero() + b,
        LinearCombination::zero() + c
    );
    assert!(cs.is_satisfied());
    assert_eq!(cs.num_constraints(), 1);

    cs.set("a/var", Fr::from_str("4").unwrap());

    let one = cs.one();
    cs.enforce(
        || "eq",
        LinearCombination::zero() + a,
        LinearCombination::zero() + one,
        LinearCombination::zero() + b
    );

    assert!(!cs.is_satisfied());
    assert!(cs.which_is_unsatisfied() == Some("mult"));

    assert!(cs.get("product") == Fr::from_str("40").unwrap());

    cs.set("product", Fr::from_str("16").unwrap());
    assert!(cs.is_satisfied());

    {
        let mut cs = cs.namespace(|| "test1");
        let mut cs = cs.namespace(|| "test2");
        cs.alloc(|| "hehe", || Ok(Fr::one())).unwrap();
    }

    assert!(cs.get("test1/test2/hehe") == Fr::one());
}
