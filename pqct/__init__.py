"""PQ-CT research reference implementation; not production cryptography."""

from .challenge import ChallengeError, SparseChallenge, sample_sparse_challenge
from .cycle_masking import (
    CycleMask,
    derive_cycle_mask,
    mask_relation,
    reconstruct_first_response,
    relation_response_is_exactly_zero,
)
from .relations import (
    account_conservation,
    bit_columns,
    packed_bit_relation,
    weighted_relation,
)
from .binary_relation import (
    BinaryIdentity,
    batch_linear_opening,
    build_binary_identity,
    verify_binary_identity,
)
from .balance_composition import BalanceColumns
from .balance_composition import BalanceCompositionError
from .balance_composition import MaskedBalanceResponse
from .balance_composition import SignedAmount
from .balance_composition import build_balance_columns
from .balance_composition import build_masked_balance_response
from .balance_transcript import AmountCommitment
from .balance_transcript import BalanceTranscript
from .balance_transcript import BalanceTranscriptError
from .balance_transcript import build_balance_transcript
from .linear_equation_transcript import CycleMaskCommitment
from .linear_equation_transcript import LinearEquationError
from .linear_equation_transcript import build_cycle_mask_commitment
from .linear_equation_transcript import check_commitment_equation
from .linear_equation_transcript import compute_response_tail
from .linear_equation_transcript import f0_in_canonical_range
from .linear_equation_transcript import reconstruct_f0_over_integers
from .protocol5 import Protocol5Error
from .protocol5 import Protocol5Parameters
from .protocol5 import Protocol5Proof
from .protocol5 import Protocol5Result
from .protocol5 import Protocol5Verification
from .protocol5 import compute_sign_max
from .protocol5 import compute_t3
from .protocol5 import derive_protocol5_challenge
from .protocol5 import derive_ring_cycle_mask
from .protocol5 import prove_linear_equation
from .protocol5 import ring_cycle_mask_weighted_sum_is_zero
from .protocol5 import verify_linear_equation
from .binary_protocol1 import Protocol1Error, Protocol1Parameters, Protocol1Proof, derive_protocol1_challenge, prove_protocol1, verify_protocol1
from .binary_protocol1_ring import (RingProtocol1Error, RingProtocol1Parameters, RingProtocol1Proof, build_protocol1_ring_transcript, prove_protocol1_ring, verify_protocol1_ring)
from .binary_hmc import (
    BinaryProof,
    BinaryProofParameters,
    BinaryTranscriptError,
    derive_binary_challenge,
    prove_binary,
    verify_binary,
)
from .gaussian import GaussianError, GaussianProfile, empirical_histogram, sample_truncated, shake_source
from .goodness_of_fit import ChiSquareResult
from .goodness_of_fit import GoodnessOfFitError
from .goodness_of_fit import chi_square_goodness_of_fit
from .goodness_of_fit import chi_square_p_value
from .goodness_of_fit import regularized_gamma_q
from .hmc import (
    HMCError,
    HMCKey,
    bounded_ring_element,
    centered_coefficients,
    infinity_norm,
    verify_opening as verify_hmc_opening,
    verify_relaxed_opening,
)
from .hmc_binding_experiment import (
    BindingCollision,
    BindingExperimentError,
    BindingSearchResult,
    search_relaxed_collisions,
)
from .hmc_binding_reduction import BindingParameterCheck
from .hmc_binding_reduction import BindingReductionError
from .hmc_binding_reduction import MSISInstance
from .hmc_binding_reduction import check_binding_parameters
from .hmc_binding_reduction import derive_msis_solution
from .lattice_estimate import LatticeEstimateError
from .lattice_estimate import SISHardnessEstimate
from .lattice_estimate import beta_from_delta
from .lattice_estimate import core_svp_bits
from .lattice_estimate import delta_from_beta
from .lattice_estimate import estimate_sis_hardness
from .protocol1_binary_relation import BinaryRelationError
from .protocol1_binary_relation import BinaryWitnessCheck
from .protocol1_binary_relation import extract_binary_witness_row
from .hmc_transcript import (
    HMCProof,
    HMCTranscriptError,
    derive_hmc_challenge,
    prove_hmc_relation,
    verify_hmc_relation,
)
from .independent_oracle import exhaustive_scalar_relations, matrix_commit, negacyclic_mul
from .protocol1_independent_oracle import (
    IndependentProtocol1Error,
    IndependentProtocol1Proof,
    IndependentProtocol1Transcript,
    RawHMCKey,
    build_independent_transcript,
    verify_independent_transcript,
)
from .matrix_generation import generate_hmc_key
from .parameterization import ParameterCandidate, candidate_set, render_report
from .protocol1_sampling import (
    FiniteDiscreteGaussian,
    Protocol1DistributionParameters,
    Protocol1Masks,
    Protocol1RejectionPlan,
    RejectionPolicy,
    SamplingError,
    XofByteSource,
    accept_rejection,
    build_rejection_plan,
    rejection_log_probability,
    sample_protocol1_masks,
)
from .protocol1_extraction import (
    ExtractionError,
    FirstLayerExtraction,
    RelaxedOpening,
    SecondLayerExtraction,
    SecondLayerPairExtraction,
    extract_first_layer_s2,
    extract_second_layer,
    extract_second_layer_pair,
    validate_first_layer_relation,
    validate_pairwise_consistency,
    validate_pairwise_negation,
    validate_third_x_transcript,
)
from .protocol1_family import (
    FamilyError,
    ResponseAudit,
    SecondLayerFamily,
    TwoLayerExtractionTree,
    WraparoundReport,
    audit_response,
    build_second_layer_family,
    build_two_layer_extraction_tree,
    extract_checked_second_layer,
)
from .protocol1_rejection_audit import RejectionAuditError, RejectionTupleAudit, build_rejection_tuple_audit
from .protocol1_sampled import SampledProtocol1Error, SampledProtocol1Result, prove_protocol1_ring_sampled
from .protocol1_simulator import SimulationError, SimulatedProtocol1, simulate_protocol1_ring
from .protocol1_shvzk_compare import (
    FixedChallengeComparison,
    SHVZKComparisonError,
    compare_fixed_challenge,
    encode_fixed_transcript,
    encode_response_tuple,
)
from .statistical_distance import (
    StatisticalDistanceError,
    conditioned_tv_upper_bound,
    finite_normalizer,
    gaussian_product_tv_upper_bound,
    inverse_cdf_grid_tv_upper_bound,
    omitted_unnormalized_mass_upper_bound,
    product_tv_union_bound,
    truncation_tv_upper_bound,
)
from .shvzk_empirical_stats import (
    CollisionAwareStats,
    EmpiricalStatsError,
    MarginalIntegerStats,
    collision_aware_digest_stats,
    collision_aware_stats,
    marginal_integer_stats,
)
from .ring_challenge import RingChallengeError, RingChallengeParameters, challenge_ring_element, derive_ring_challenge
from .reduced_transcript import (
    ReducedProof,
    ReducedRelationParameters,
    SequenceIntSampler,
    SystemIntSampler,
    ToyVectorCommitmentKey,
    derive_challenge,
    prove_reduced_relation,
    verify_reduced_relation,
)
from .parameters import (
    GaoPaperProfile,
    ParameterError,
    ToyProfile,
    cycle_mask_bound,
    response_bound,
)
from .rejection_sampling import (
    RejectionSample,
    RejectionSamplingError,
    acceptance_probability,
    accept_candidate,
    accepts,
    log_acceptance_ratio,
)
from .ring_commitment import (
    Matrix,
    RingElement,
    ToyParameters,
    Vector,
    commit,
    hash_transcript,
    open_commitment,
    verify_opening,
)

__all__ = [
    "Matrix",
    "RingElement",
    "ToyParameters",
    "Vector",
    "commit",
    "hash_transcript",
    "open_commitment",
    "verify_opening",
]
