use miden_vm::VMResult;
use std::mem;

// Used to restore the roothash, and send the roothash back with the security level
pub fn restore_roothash(vm_result: VMResult) -> String {
    let stack_vec = vm_result
        .outputs
        .stack
        .iter()
        .map(|init| init.parse::<u64>().unwrap())
        .collect();

    let outputs = compute_roothash(stack_vec);
    return hex::encode(outputs);
}

// helper function -- help compute roothash from outputs
fn compute_roothash(outputs: Vec<u64>) -> Vec<u8> {
    let mut outputs_u64: Vec<u64> = Vec::new();
    // the roothash should be the first 4 elements
    for i in 0..4 {
        outputs_u64.push(outputs[i])
    }

    outputs_u64.reverse();

    let vec8 = unsafe {
        let ratio = mem::size_of::<u64>() / mem::size_of::<u8>();
        let length = outputs_u64.len() * ratio;
        let capacity = outputs_u64.capacity() * ratio;
        let ptr = outputs_u64.as_mut_ptr() as *mut u8;

        // Don't run the destructor for vec64
        mem::forget(outputs_u64);

        // Construct new Vec
        Vec::from_raw_parts(ptr, length, capacity)
    };
    return vec8;
}
