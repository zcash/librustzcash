pub mod opcodes;
use opcodes::*;

/// Maximum allowed size of data (in bytes) that can be pushed to the stack.
pub const MAX_SCRIPT_ELEMENT_SIZE: usize = 520;

/// Maximum allowed script length in bytes.
pub const MAX_SCRIPT_SIZE: usize = 10000;

// Threshold for nLockTime: below this value it is interpreted as block number,
// otherwise as UNIX timestamp.
pub const LOCKTIME_THRESHOLD: usize = 500000000; // Tue Nov  5 00:53:20 1985 UTC

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum ScriptError {
    ReadError {
        expected_bytes: usize,
        available_bytes: usize,
    },
    InvalidOpcode,
    PushSize,
    OpCount,
    DisabledOpcode,
    ScriptSize,
    MinimalData,
    StackSize,
    UnbalancedConditional,
    UpgradableNops,
    InvalidStackOperation,
    OpReturn,
}

pub struct ExecutionOptions {
    pub require_minimal_pushes: bool,
    pub enable_checklocktimeverify: bool,
    pub discourage_upgradable_nops: bool,
}

#[derive(Clone)]
pub struct Script<'a>(pub &'a [u8]);

impl<'a> Script<'a> {
    /// Returns true iff this script is P2PKH.
    pub fn is_p2pkh(&self) -> bool {
        (self.0.len() == 25)
            && (self.0[0] == Opcode::OP_DUP as u8)
            && (self.0[1] == Opcode::OP_HASH160 as u8)
            && (self.0[2] == 0x14)
            && (self.0[23] == Opcode::OP_EQUALVERIFY as u8)
            && (self.0[24] == Opcode::OP_CHECKSIG as u8)
    }

    /// Returns true iff this script is P2SH.
    pub fn is_p2sh(&self) -> bool {
        (self.0.len() == 23)
            && (self.0[0] == Opcode::OP_HASH160 as u8)
            && (self.0[1] == 0x14)
            && (self.0[22] == Opcode::OP_EQUAL as u8)
    }

    pub fn evaluate(
        &self,
        stack: &mut Vec<Vec<u8>>,
        options: &ExecutionOptions,
    ) -> Result<(), ScriptError> {
        // There's a limit on how large scripts can be.
        if self.0.len() > MAX_SCRIPT_SIZE {
            return Err(ScriptError::ScriptSize);
        }

        let mut script = (*self).clone();
        let mut push_data = vec![];

        // We keep track of how many operations have executed so far to prevent
        // expensive-to-verify scripts
        let mut op_count = 0;

        // This keeps track of the conditional flags at each nesting level
        // during execution. If we're in a branch of execution where *any*
        // of these conditionals are false, we ignore opcodes unless those
        // opcodes direct control flow (OP_IF, OP_ELSE, etc.).
        let mut exec: Vec<bool> = vec![];

        let mut alt_stack: Vec<Vec<u8>> = vec![];

        // Main execution loop
        while !script.0.is_empty() {
            // Are we in an executing branch of the script?
            let executing = exec.iter().all(|value| *value);

            // Consume an opcode
            let operation = parse_opcode(&mut script.0, Some(&mut push_data))?;

            match operation {
                Operation::PushBytes(raw_opcode) => {
                    // There's a limit to the size of the values we'll put on
                    // the stack.
                    if push_data.len() > MAX_SCRIPT_ELEMENT_SIZE {
                        return Err(ScriptError::PushSize);
                    }

                    if executing {
                        // Data is being pushed to the stack here; we may need to check
                        // that the minimal script size was used to do so if our caller
                        // requires it.
                        if options.require_minimal_pushes
                            && !check_minimal_push(&push_data, raw_opcode)
                        {
                            return Err(ScriptError::MinimalData);
                        }

                        stack.push(push_data.clone());
                    }
                }
                Operation::Constant(value) => {
                    todo!()
                }

                // Invalid and disabled opcodes do technically contribute to
                // op_count, but they always result in a failed script execution
                // anyway.
                Operation::Invalid => return Err(ScriptError::InvalidOpcode),
                Operation::Disabled => return Err(ScriptError::DisabledOpcode),

                Operation::Opcode(opcode) => {
                    // There's a limit on how many operations can execute in a
                    // script. We consider opcodes beyond OP_16 to be "actual"
                    // opcodes as ones below that just involve data pushes. All
                    // opcodes defined by the Opcode enum qualify except for
                    // OP_RESERVED, which is not beyond OP_16.
                    //
                    // Note: operations even if they are not executed but are
                    // still present in the script count toward this count.
                    if opcode != Opcode::OP_RESERVED {
                        op_count += 1;
                        if op_count > 201 {
                            return Err(ScriptError::OpCount);
                        }
                    }

                    if executing || opcode.is_control_flow_opcode() {
                        match opcode {
                            Opcode::OP_RESERVED
                            | Opcode::OP_VER
                            | Opcode::OP_RESERVED1
                            | Opcode::OP_RESERVED2 => {
                                // These are considered "invalid" opcodes but
                                // only inside of *executing* OP_IF branches of
                                // the script.
                                return Err(ScriptError::InvalidOpcode);
                            }
                            Opcode::OP_NOP => {
                                // Do nothing.
                            }
                            Opcode::OP_NOP1
                            | Opcode::OP_NOP3
                            | Opcode::OP_NOP4
                            | Opcode::OP_NOP5
                            | Opcode::OP_NOP6
                            | Opcode::OP_NOP7
                            | Opcode::OP_NOP8
                            | Opcode::OP_NOP9
                            | Opcode::OP_NOP10 => {
                                // Do nothing, though if the caller wants to
                                // prevent people from using these NOPs (as part
                                // of a standard tx rule, for example) they can
                                // enable `discourage_upgradable_nops` to turn
                                // these opcodes into errors.
                                if options.discourage_upgradable_nops {
                                    return Err(ScriptError::UpgradableNops);
                                }
                            }
                            Opcode::OP_CHECKLOCKTIMEVERIFY => {
                                // This was originally OP_NOP2 but has been repurposed
                                // for OP_CHECKLOCKTIMEVERIFY. So, we should act based
                                // on whether or not CLTV has been activated in a soft
                                // fork.
                                if !options.enable_checklocktimeverify {
                                    if options.discourage_upgradable_nops {
                                        return Err(ScriptError::UpgradableNops);
                                    }
                                } else {
                                    todo!()
                                }
                            }
                            Opcode::OP_IF | Opcode::OP_NOTIF => {
                                let mut value = false;
                                if executing {
                                    if stack.is_empty() {
                                        return Err(ScriptError::UnbalancedConditional);
                                    }
                                    todo!()
                                }
                                exec.push(value);
                            }
                            Opcode::OP_ELSE => {
                                if exec.is_empty() {
                                    return Err(ScriptError::UnbalancedConditional);
                                }

                                exec.last_mut().map(|last| *last = !*last);
                            }
                            Opcode::OP_ENDIF => {
                                if exec.is_empty() {
                                    return Err(ScriptError::UnbalancedConditional);
                                }

                                exec.pop();
                            }
                            Opcode::OP_VERIFY => {
                                if stack.is_empty() {
                                    return Err(ScriptError::InvalidStackOperation);
                                }

                                let value = stack.pop().unwrap();

                                todo!()
                            }
                            Opcode::OP_RETURN => return Err(ScriptError::OpReturn),
                            Opcode::OP_TOALTSTACK => {
                                if stack.is_empty() {
                                    return Err(ScriptError::InvalidStackOperation);
                                }

                                alt_stack.push(stack.pop().unwrap());
                            }
                            Opcode::OP_FROMALTSTACK => {
                                if alt_stack.is_empty() {
                                    return Err(ScriptError::InvalidStackOperation);
                                }

                                stack.push(alt_stack.pop().unwrap());
                            }
                            Opcode::OP_2DROP => {
                                if stack.len() < 2 {
                                    return Err(ScriptError::InvalidStackOperation);
                                }

                                stack.pop();
                                stack.pop();
                            }
                            Opcode::OP_2DUP => {
                                if stack.len() < 2 {
                                    return Err(ScriptError::InvalidStackOperation);
                                }

                                let b = stack.pop().unwrap();
                                let a = stack.pop().unwrap();
                                stack.push(a.clone());
                                stack.push(b.clone());
                                stack.push(a);
                                stack.push(b);
                            }
                            Opcode::OP_3DUP => {
                                if stack.len() < 3 {
                                    return Err(ScriptError::InvalidStackOperation);
                                }

                                let c = stack.pop().unwrap();
                                let b = stack.pop().unwrap();
                                let a = stack.pop().unwrap();
                                stack.push(a.clone());
                                stack.push(b.clone());
                                stack.push(c.clone());
                                stack.push(a);
                                stack.push(b);
                                stack.push(c);
                            }
                            Opcode::OP_2OVER => {
                                if stack.len() < 4 {
                                    return Err(ScriptError::InvalidStackOperation);
                                }

                                let d = stack.pop().unwrap();
                                let c = stack.pop().unwrap();
                                let b = stack.pop().unwrap();
                                let a = stack.pop().unwrap();
                                stack.push(a.clone());
                                stack.push(b.clone());
                                stack.push(c);
                                stack.push(d);
                                stack.push(a);
                                stack.push(b);
                            }
                            Opcode::OP_2ROT => {
                                if stack.len() < 6 {
                                    return Err(ScriptError::InvalidStackOperation);
                                }

                                let f = stack.pop().unwrap();
                                let e = stack.pop().unwrap();
                                let d = stack.pop().unwrap();
                                let c = stack.pop().unwrap();
                                let b = stack.pop().unwrap();
                                let a = stack.pop().unwrap();
                                stack.push(c);
                                stack.push(d);
                                stack.push(e);
                                stack.push(f);
                                stack.push(a);
                                stack.push(b);
                            }
                            Opcode::OP_2SWAP => {
                                if stack.len() < 4 {
                                    return Err(ScriptError::InvalidStackOperation);
                                }

                                let d = stack.pop().unwrap();
                                let c = stack.pop().unwrap();
                                let b = stack.pop().unwrap();
                                let a = stack.pop().unwrap();
                                stack.push(c);
                                stack.push(d);
                                stack.push(a);
                                stack.push(b);
                            }
                            Opcode::OP_IFDUP => {
                                if stack.is_empty() {
                                    return Err(ScriptError::InvalidStackOperation);
                                }

                                todo!()
                            }
                            Opcode::OP_DEPTH => {
                                todo!()
                            }
                            Opcode::OP_DROP => {
                                if stack.is_empty() {
                                    return Err(ScriptError::InvalidStackOperation);
                                }

                                stack.pop();
                            }
                            Opcode::OP_DUP => {
                                if stack.is_empty() {
                                    return Err(ScriptError::InvalidStackOperation);
                                }

                                let a = stack.pop().unwrap();
                                stack.push(a.clone());
                                stack.push(a);
                            }
                            Opcode::OP_NIP => {
                                if stack.len() < 2 {
                                    return Err(ScriptError::InvalidStackOperation);
                                }

                                let b = stack.pop().unwrap();
                                stack.pop();
                                stack.push(b);
                            }
                            Opcode::OP_OVER => {
                                if stack.len() < 2 {
                                    return Err(ScriptError::InvalidStackOperation);
                                }

                                let b = stack.pop().unwrap();
                                let a = stack.pop().unwrap();
                                stack.push(a.clone());
                                stack.push(b);
                                stack.push(a);
                            }
                            Opcode::OP_PICK | Opcode::OP_ROLL => {
                                todo!()
                            }
                            Opcode::OP_ROT => {
                                todo!()
                            }
                            Opcode::OP_SWAP => {
                                if stack.len() < 2 {
                                    return Err(ScriptError::InvalidStackOperation);
                                }

                                let b = stack.pop().unwrap();
                                let a = stack.pop().unwrap();
                                stack.push(b);
                                stack.push(a);
                            }
                            Opcode::OP_TUCK => {
                                if stack.len() < 2 {
                                    return Err(ScriptError::InvalidStackOperation);
                                }

                                let b = stack.pop().unwrap();
                                let a = stack.pop().unwrap();
                                stack.push(b.clone());
                                stack.push(a);
                                stack.push(b);
                            }
                            Opcode::OP_SIZE => {
                                todo!()
                            }
                            Opcode::OP_EQUAL | Opcode::OP_EQUALVERIFY => {
                                if stack.len() < 2 {
                                    return Err(ScriptError::InvalidStackOperation);
                                }

                                todo!()
                            }
                            Opcode::OP_1ADD
                            | Opcode::OP_1SUB
                            | Opcode::OP_NEGATE
                            | Opcode::OP_ABS
                            | Opcode::OP_NOT
                            | Opcode::OP_0NOTEQUAL => {
                                todo!()
                            }
                            Opcode::OP_ADD
                            | Opcode::OP_SUB
                            | Opcode::OP_BOOLAND
                            | Opcode::OP_BOOLOR
                            | Opcode::OP_NUMEQUAL
                            | Opcode::OP_NUMEQUALVERIFY
                            | Opcode::OP_NUMNOTEQUAL
                            | Opcode::OP_LESSTHAN
                            | Opcode::OP_GREATERTHAN
                            | Opcode::OP_LESSTHANOREQUAL
                            | Opcode::OP_GREATERTHANOREQUAL
                            | Opcode::OP_MIN
                            | Opcode::OP_MAX => {
                                todo!()
                            }
                            Opcode::OP_WITHIN => {
                                todo!()
                            }
                            Opcode::OP_RIPEMD160
                            | Opcode::OP_SHA1
                            | Opcode::OP_SHA256
                            | Opcode::OP_HASH160
                            | Opcode::OP_HASH256 => {
                                todo!()
                            }
                            Opcode::OP_CHECKSIG | Opcode::OP_CHECKSIGVERIFY => {
                                todo!()
                            }
                            Opcode::OP_CHECKMULTISIG | Opcode::OP_CHECKMULTISIGVERIFY => {
                                todo!()
                            }
                        }
                    }
                }
            }

            // There's a limit to how many items can be added to the stack and
            // alt stack. This limit is enforced upon finishing the execution of
            // an opcode.
            if stack.len() + alt_stack.len() > 1000 {
                return Err(ScriptError::StackSize);
            }
        }

        if exec.is_empty() {
            Ok(())
        } else {
            Err(ScriptError::UnbalancedConditional)
        }
    }
}

fn check_minimal_push(data: &[u8], raw_opcode: u8) -> bool {
    todo!()
}
