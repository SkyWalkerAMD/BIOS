/* EXPERIMENT ONLY. No entry point, firmware services, or live installer.
 * The test maps this import-free DLL into Unicorn together with original ACE
 * AMITSE. Authorization stays entirely outside this result aggregation scope.
 */
typedef unsigned long long U64;
typedef unsigned int U32;
typedef U64 (*NATIVE_SAVE)(U64, U64, U64, U64);
#define EXPORT __declspec(dllexport)

typedef struct SAVE_SCOPE {
    struct SAVE_SCOPE *previous;
    U64 first_denial;
} SAVE_SCOPE;

EXPORT NATIVE_SAVE save_original;
EXPORT NATIVE_SAVE fixture_save_entry;
EXPORT NATIVE_SAVE save_stay_original;
EXPORT SAVE_SCOPE *save_top;
EXPORT SAVE_SCOPE *save_action_top;
EXPORT volatile unsigned char *fixture_dirty_82789, *fixture_dirty_82738;
EXPORT U32 save_depth, max_depth_seen, wrapper_entries, original_calls;
EXPORT U32 overflow_count, unscoped_denials, fixture_calls;
EXPORT U64 fixture_status, last_denial;
EXPORT U32 fixture_mark_denial, fixture_nested_once;
EXPORT U32 fixture_first_only;
EXPORT void *fixture_target_name;
EXPORT U32 fixture_guard_calls;
EXPORT U64 fixture_nested_status, fixture_nested_return;
EXPORT U32 fixture_nested_mark;

EXPORT void save_record_denial(U64 status) {
    if (save_action_top && !save_action_top->first_denial)
        save_action_top->first_denial = status;
    if (!save_top) {
        unscoped_denials++;
        return;
    }
    if (!save_top->first_denial) save_top->first_denial = status;
}

static void preserve_changed(unsigned char old_changed, unsigned char old_unsaved) {
    if (fixture_dirty_82789)
        *fixture_dirty_82789 = old_changed ? old_changed : 1;
    if (fixture_dirty_82738)
        *fixture_dirty_82738 = old_unsaved ? old_unsaved : 1;
}

EXPORT U64 save_wrapper(U64 a, U64 b, U64 c, U64 d) {
    SAVE_SCOPE scope;
    U64 result;
    unsigned char changed = fixture_dirty_82789 ? *fixture_dirty_82789 : 0;
    unsigned char unsaved = fixture_dirty_82738 ? *fixture_dirty_82738 : 0;
    wrapper_entries++;
    if (save_depth >= 16) {
        /* Retain the original call even on tracking overflow. Existing guards
         * still enforce authorization; the tracked parent receives failure. */
        overflow_count++;
        save_record_denial(0x800000000000000fULL);
        original_calls++;
        result = save_original(a, b, c, d);
        return result & ~255ULL;
    }
    scope.previous = save_top;
    scope.first_denial = 0;
    save_top = &scope;
    save_depth++;
    if (save_depth > max_depth_seen) max_depth_seen = save_depth;
    original_calls++;
    result = save_original(a, b, c, d);
    save_top = scope.previous;
    save_depth--;
    if (scope.first_denial) {
        last_denial = scope.first_denial;
        if (save_top && !save_top->first_denial)
            save_top->first_denial = scope.first_denial;
        result &= ~255ULL;
        preserve_changed(changed, unsaved);
    }
    return result;
}

/* The common iterator returns before SaveStay clears its native unsaved flag.
 * This separate action wrapper preserves that flag after the original caller.
 */
EXPORT U64 save_stay_wrapper(U64 a, U64 b, U64 c, U64 d) {
    SAVE_SCOPE action;
    U64 result;
    unsigned char changed = fixture_dirty_82789 ? *fixture_dirty_82789 : 0;
    unsigned char unsaved = fixture_dirty_82738 ? *fixture_dirty_82738 : 0;
    action.previous = save_action_top;
    action.first_denial = 0;
    save_action_top = &action;
    result = save_stay_original(a, b, c, d);
    save_action_top = action.previous;
    if (action.first_denial) {
        preserve_changed(changed, unsaved);
        if (save_action_top && !save_action_top->first_denial)
            save_action_top->first_denial = action.first_denial;
    }
    return result;
}

/* I/O fixture. It is not a replacement for the production variable guard. */
EXPORT U64 fixture_set_variable(void *name, void *guid, U32 attributes,
                                U64 bytes, void *value) {
    U64 this_status = fixture_status;
    U32 this_mark = fixture_mark_denial;
    (void)name; (void)guid; (void)attributes; (void)bytes; (void)value;
    if (fixture_target_name && name != fixture_target_name) {
        this_status = 0;
        this_mark = 0;
    } else if (fixture_first_only && fixture_guard_calls) {
        this_status = 0;
        this_mark = 0;
    }
    if (!fixture_target_name || name == fixture_target_name) fixture_guard_calls++;
    fixture_calls++;
    if (fixture_nested_once) {
        fixture_nested_once--;
        fixture_status = fixture_nested_status;
        fixture_mark_denial = fixture_nested_mark;
        fixture_nested_return = fixture_save_entry(0, 0, 0, 0);
        fixture_status = this_status;
        fixture_mark_denial = this_mark;
    }
    if (this_mark) save_record_denial(this_status);
    return this_status;
}
