"""
Feature extraction from Suricata flow events for CICIDS2017-trained models.

Converts Suricata EVE JSON flow events into the feature vector format expected
by ML models trained on the CICIDS2017 dataset.

The feature names are loaded from the persisted feature_columns.joblib file
when available, ensuring that the StandardScaler receives the same feature
names that were used during training.
"""

import logging
import numpy as np
import pandas as pd

from typing import Dict, Any, Optional, List
from dataclasses import dataclass
from datetime import datetime
import joblib
from pathlib import Path


logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Internal feature names used by the extractor
# ---------------------------------------------------------------------------

FEATURE_COLUMNS = [
    "flow_duration",
    "total_fwd_packets",
    "total_bwd_packets",
    "total_length_fwd_packets",
    "total_length_bwd_packets",
    "flow_bytes_per_s",
    "flow_packets_per_s",
]


# ---------------------------------------------------------------------------
# Actual feature names used during model/scaler training
# ---------------------------------------------------------------------------

DEFAULT_MODEL_FEATURE_COLUMNS = [
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Total Length of Fwd Packets",
    "Total Length of Bwd Packets",
    "Flow Bytes/s",
    "Flow Packets/s",
]


# ---------------------------------------------------------------------------
# Flow feature container
# ---------------------------------------------------------------------------

@dataclass
class FlowFeatures:
    """Container for extracted flow features."""

    flow_duration: float
    total_fwd_packets: int
    total_bwd_packets: int
    total_length_fwd_packets: int
    total_length_bwd_packets: int
    flow_bytes_per_s: float
    flow_packets_per_s: float

    def to_array(self) -> np.ndarray:
        """
        Convert features to numpy array in the correct column order.

        Returns:
            1D numpy array containing 7 features.
        """

        return np.array(
            [
                self.flow_duration,
                self.total_fwd_packets,
                self.total_bwd_packets,
                self.total_length_fwd_packets,
                self.total_length_bwd_packets,
                self.flow_bytes_per_s,
                self.flow_packets_per_s,
            ],
            dtype=np.float64,
        )


# ---------------------------------------------------------------------------
# Feature Extractor
# ---------------------------------------------------------------------------

class FeatureExtractor:
    """
    Extracts CICIDS2017-compatible features from Suricata flow events.

    The extractor produces the same 7 features used by the trained XGBoost
    model:

        1. Flow Duration
        2. Total Fwd Packets
        3. Total Backward Packets
        4. Total Length of Fwd Packets
        5. Total Length of Bwd Packets
        6. Flow Bytes/s
        7. Flow Packets/s

    The persisted StandardScaler is applied using a pandas DataFrame so that
    sklearn receives the exact feature names it saw during training.
    """

    def __init__(
        self,
        scaler_path: Optional[str] = None,
        feature_columns_path: Optional[str] = None,
    ):
        """
        Initialize the feature extractor.

        Args:
            scaler_path:
                Path to the fitted StandardScaler joblib file.

            feature_columns_path:
                Path to feature_columns.joblib.

        Raises:
            FileNotFoundError:
                If a specified file does not exist.
        """

        self.scaler = None

        # ---------------------------------------------------------------
        # Default paths
        # ---------------------------------------------------------------

        if feature_columns_path is None:
            feature_columns_path = "models/feature_columns.joblib"

        # ---------------------------------------------------------------
        # Load the actual training feature names
        # ---------------------------------------------------------------

        self.model_feature_columns = DEFAULT_MODEL_FEATURE_COLUMNS.copy()

        feature_columns_file = Path(feature_columns_path)

        if feature_columns_file.exists():

            try:
                loaded_columns = joblib.load(feature_columns_file)

                if isinstance(loaded_columns, (list, tuple)):

                    loaded_columns = list(loaded_columns)

                    if len(loaded_columns) == len(FEATURE_COLUMNS):

                        self.model_feature_columns = loaded_columns

                        logger.info(
                            "Loaded training feature names from %s",
                            feature_columns_file,
                        )

                    else:

                        logger.warning(
                            "feature_columns.joblib contains %d features, "
                            "but extractor expects %d. Using defaults.",
                            len(loaded_columns),
                            len(FEATURE_COLUMNS),
                        )

                else:

                    logger.warning(
                        "Invalid feature_columns.joblib format. "
                        "Using default feature names."
                    )

            except Exception as e:

                logger.warning(
                    "Could not load feature_columns.joblib: %s. "
                    "Using default feature names.",
                    e,
                )

        else:

            logger.warning(
                "Feature columns file not found: %s. "
                "Using default training feature names.",
                feature_columns_file,
            )

        # ---------------------------------------------------------------
        # Load scaler
        # ---------------------------------------------------------------

        if scaler_path:

            scaler_path = Path(scaler_path)

            if not scaler_path.exists():

                raise FileNotFoundError(
                    f"Scaler file not found: {scaler_path}"
                )

            try:

                self.scaler = joblib.load(scaler_path)

                logger.info(
                    "Loaded StandardScaler from %s",
                    scaler_path,
                )

                # -------------------------------------------------------
                # Verify scaler feature count
                # -------------------------------------------------------

                if hasattr(self.scaler, "n_features_in_"):

                    expected = len(FEATURE_COLUMNS)
                    actual = self.scaler.n_features_in_

                    if actual != expected:

                        logger.warning(
                            "Scaler expects %d features but extractor "
                            "provides %d.",
                            actual,
                            expected,
                        )

                    else:

                        logger.info(
                            "Scaler compatibility verified: %d features",
                            expected,
                        )

                # -------------------------------------------------------
                # Check feature names stored by sklearn
                # -------------------------------------------------------

                if hasattr(self.scaler, "feature_names_in_"):

                    scaler_names = list(
                        self.scaler.feature_names_in_
                    )

                    if scaler_names != self.model_feature_columns:

                        logger.warning(
                            "Scaler feature names differ from "
                            "feature_columns.joblib."
                        )

                        logger.warning(
                            "Scaler names: %s",
                            scaler_names,
                        )

                        logger.warning(
                            "Expected names: %s",
                            self.model_feature_columns,
                        )

            except Exception as e:

                logger.error(
                    "Failed to load scaler: %s",
                    e,
                )

                raise

    # -------------------------------------------------------------------
    # Protocol conversion
    # -------------------------------------------------------------------

    @staticmethod
    def _get_protocol_number(proto_name: str) -> int:
        """
        Convert protocol name to IP protocol number.

        TCP   = 6
        UDP   = 17
        ICMP  = 1
        ICMPv6 = 58
        Other = 0
        """

        proto_map = {
            "TCP": 6,
            "UDP": 17,
            "ICMP": 1,
            "ICMPv6": 58,
        }

        if not proto_name:
            return 0

        return proto_map.get(
            proto_name.upper(),
            0,
        )

    # -------------------------------------------------------------------
    # Timestamp parser
    # -------------------------------------------------------------------

    @staticmethod
    def _parse_timestamp(
        ts_str: str,
    ) -> Optional[datetime]:
        """
        Parse a Suricata timestamp.

        Supports:

            2023-01-01T12:00:00.123456+0000
            2023-01-01T12:00:00+0000
        """

        if not ts_str:
            return None

        try:

            formats = [
                "%Y-%m-%dT%H:%M:%S.%f%z",
                "%Y-%m-%dT%H:%M:%S%z",
            ]

            for fmt in formats:

                try:

                    return datetime.strptime(
                        ts_str,
                        fmt,
                    )

                except ValueError:
                    continue

            return None

        except Exception as e:

            logger.debug(
                "Failed to parse timestamp '%s': %s",
                ts_str,
                e,
            )

            return None

    # -------------------------------------------------------------------
    # Extract features from one Suricata event
    # -------------------------------------------------------------------

    def extract_from_event(
        self,
        event: Dict[str, Any],
    ) -> Optional[FlowFeatures]:
        """
        Extract the 7 ML features from a Suricata flow event.

        Returns:
            FlowFeatures object or None if extraction fails.
        """

        try:

            # -----------------------------------------------------------
            # Validate event type
            # -----------------------------------------------------------

            if event.get("event_type") != "flow":

                logger.debug(
                    "Ignoring non-flow event: %s",
                    event.get("event_type"),
                )

                return None

            # -----------------------------------------------------------
            # Get flow object
            # -----------------------------------------------------------

            flow = event.get("flow", {})

            if not flow:

                logger.warning(
                    "Flow event missing 'flow' field"
                )

                return None

            # -----------------------------------------------------------
            # Packet counts
            # -----------------------------------------------------------

            fwd_packets = flow.get(
                "pkts_toserver",
                0,
            )

            bwd_packets = flow.get(
                "pkts_toclient",
                0,
            )

            # -----------------------------------------------------------
            # Byte counts
            # -----------------------------------------------------------

            fwd_bytes = flow.get(
                "bytes_toserver",
                0,
            )

            bwd_bytes = flow.get(
                "bytes_toclient",
                0,
            )

            # -----------------------------------------------------------
            # Convert to numeric values
            # -----------------------------------------------------------

            fwd_packets = float(fwd_packets or 0)
            bwd_packets = float(bwd_packets or 0)

            fwd_bytes = float(fwd_bytes or 0)
            bwd_bytes = float(bwd_bytes or 0)

            # -----------------------------------------------------------
            # Calculate duration
            # -----------------------------------------------------------

            start_str = flow.get("start")
            end_str = flow.get("end")

            duration = 0.0

            if start_str and end_str:

                start = self._parse_timestamp(
                    start_str
                )

                end = self._parse_timestamp(
                    end_str
                )

                if start and end:

                    duration = (
                        end - start
                    ).total_seconds()

            # -----------------------------------------------------------
            # Fallback to age
            # -----------------------------------------------------------

            if duration <= 0:

                duration = float(
                    flow.get("age", 0.0) or 0.0
                )

            # -----------------------------------------------------------
            # Prevent division by zero
            # -----------------------------------------------------------

            if duration <= 0:

                duration = 0.001

            # -----------------------------------------------------------
            # Derived features
            # -----------------------------------------------------------

            total_bytes = (
                fwd_bytes +
                bwd_bytes
            )

            total_packets = (
                fwd_packets +
                bwd_packets
            )

            bytes_per_s = (
                total_bytes /
                duration
            )

            packets_per_s = (
                total_packets /
                duration
            )

            # -----------------------------------------------------------
            # Create feature object
            # -----------------------------------------------------------

            features = FlowFeatures(

                flow_duration=duration,

                total_fwd_packets=int(
                    fwd_packets
                ),

                total_bwd_packets=int(
                    bwd_packets
                ),

                total_length_fwd_packets=int(
                    fwd_bytes
                ),

                total_length_bwd_packets=int(
                    bwd_bytes
                ),

                flow_bytes_per_s=bytes_per_s,

                flow_packets_per_s=packets_per_s,
            )

            return features

        except Exception as e:

            logger.error(
                "Error extracting features: %s",
                e,
                exc_info=True,
            )

            return None

    # -------------------------------------------------------------------
    # Convert numpy array to DataFrame
    # -------------------------------------------------------------------

    def _to_dataframe(
        self,
        feature_array: np.ndarray,
    ) -> pd.DataFrame:
        """
        Convert extracted features to a pandas DataFrame using the exact
        column names used during model training.

        This prevents sklearn's:

            X does not have valid feature names

        warning.
        """

        feature_array = np.asarray(
            feature_array,
            dtype=np.float64,
        )

        if feature_array.ndim == 1:

            feature_array = feature_array.reshape(
                1,
                -1,
            )

        if feature_array.shape[1] != len(
            self.model_feature_columns
        ):

            raise ValueError(
                f"Feature count mismatch: received "
                f"{feature_array.shape[1]} features, "
                f"expected {len(self.model_feature_columns)}."
            )

        return pd.DataFrame(
            feature_array,
            columns=self.model_feature_columns,
        )

    # -------------------------------------------------------------------
    # Extract and scale one event
    # -------------------------------------------------------------------

    def extract_and_scale(
        self,
        event: Dict[str, Any],
    ) -> Optional[np.ndarray]:
        """
        Extract features from a Suricata event and apply StandardScaler.

        Returns:
            1D scaled numpy array ready for the XGBoost model.
        """

        features = self.extract_from_event(
            event
        )

        if features is None:
            return None

        feature_array = features.to_array()

        # ---------------------------------------------------------------
        # Apply scaler
        # ---------------------------------------------------------------

        if self.scaler is not None:

            try:

                feature_df = self._to_dataframe(
                    feature_array
                )

                feature_array = self.scaler.transform(
                    feature_df
                )

                feature_array = feature_array.flatten()

            except Exception as e:

                logger.error(
                    "Error applying scaler: %s",
                    e,
                )

                return None

        return feature_array

    # -------------------------------------------------------------------
    # Batch extraction
    # -------------------------------------------------------------------

    def extract_batch(
        self,
        events: List[Dict[str, Any]],
        scale: bool = True,
    ) -> tuple[np.ndarray, List[int]]:
        """
        Extract features from multiple Suricata flow events.

        Returns:
            Tuple:

                feature_matrix
                valid_indices
        """

        feature_list = []
        valid_indices = []

        # ---------------------------------------------------------------
        # Extract each event
        # ---------------------------------------------------------------

        for idx, event in enumerate(events):

            features = self.extract_from_event(
                event
            )

            if features is not None:

                feature_list.append(
                    features.to_array()
                )

                valid_indices.append(
                    idx
                )

        # ---------------------------------------------------------------
        # No valid events
        # ---------------------------------------------------------------

        if not feature_list:

            return (
                np.array(
                    []
                ).reshape(
                    0,
                    len(FEATURE_COLUMNS),
                ),
                [],
            )

        # ---------------------------------------------------------------
        # Build matrix
        # ---------------------------------------------------------------

        feature_matrix = np.vstack(
            feature_list
        )

        # ---------------------------------------------------------------
        # Apply scaler
        # ---------------------------------------------------------------

        if scale and self.scaler is not None:

            try:

                feature_df = self._to_dataframe(
                    feature_matrix
                )

                feature_matrix = self.scaler.transform(
                    feature_df
                )

            except Exception as e:

                logger.error(
                    "Error applying scaler to batch: %s",
                    e,
                )

                # Return unscaled data rather than crashing
                logger.warning(
                    "Returning unscaled feature matrix."
                )

        return (
            feature_matrix,
            valid_indices,
        )

    # -------------------------------------------------------------------
    # Feature names
    # -------------------------------------------------------------------

    def get_feature_names(
        self,
    ) -> List[str]:
        """
        Get internal feature names.
        """

        return FEATURE_COLUMNS.copy()

    # -------------------------------------------------------------------
    # Training feature names
    # -------------------------------------------------------------------

    def get_model_feature_names(
        self,
    ) -> List[str]:
        """
        Get the exact feature names used during model training.
        """

        return self.model_feature_columns.copy()

    # -------------------------------------------------------------------
    # Model compatibility
    # -------------------------------------------------------------------

    def validate_model_compatibility(
        self,
        model_path: str,
    ) -> bool:
        """
        Check whether the trained model expects the same number of features.
        """

        try:

            model = joblib.load(
                model_path
            )

            # -----------------------------------------------------------
            # Check feature count
            # -----------------------------------------------------------

            if hasattr(
                model,
                "n_features_in_",
            ):

                expected = len(
                    FEATURE_COLUMNS
                )

                actual = model.n_features_in_

                if actual != expected:

                    logger.error(
                        "Model incompatibility: model expects %d "
                        "features but extractor provides %d",
                        actual,
                        expected,
                    )

                    return False

                logger.info(
                    "Model compatibility verified: %d features",
                    expected,
                )

            else:

                logger.warning(
                    "Model does not have n_features_in_ attribute; "
                    "cannot verify feature count."
                )

            return True

        except Exception as e:

            logger.error(
                "Error validating model: %s",
                e,
            )

            return False


# ---------------------------------------------------------------------------
# Standalone test
# ---------------------------------------------------------------------------

def main():
    """
    Standalone test for the FeatureExtractor.
    """

    logging.basicConfig(
        level=logging.INFO,
        format=(
            "%(asctime)s - "
            "%(name)s - "
            "%(levelname)s - "
            "%(message)s"
        ),
    )

    print("=" * 70)
    print("FEATURE EXTRACTOR TEST")
    print("=" * 70)

    # ---------------------------------------------------------------
    # Create extractor
    # ---------------------------------------------------------------

    try:

        extractor = FeatureExtractor(
            scaler_path="models/scaler.joblib",
            feature_columns_path="models/feature_columns.joblib",
        )

    except Exception as e:

        print(
            f"\nERROR: Could not initialize feature extractor:\n{e}"
        )

        return

    # ---------------------------------------------------------------
    # Print feature names
    # ---------------------------------------------------------------

    print("\nInternal feature names:")

    for name in extractor.get_feature_names():

        print(f"  {name}")

    print("\nTraining feature names:")

    for name in extractor.get_model_feature_names():

        print(f"  {name}")

    # ---------------------------------------------------------------
    # Sample Suricata event
    # ---------------------------------------------------------------

    sample_event = {

        "timestamp":
            "2023-01-01T12:00:05.500000+0000",

        "event_type":
            "flow",

        "src_ip":
            "192.168.1.100",

        "src_port":
            54321,

        "dest_ip":
            "93.184.216.34",

        "dest_port":
            80,

        "proto":
            "TCP",

        "flow": {

            "pkts_toserver":
                150,

            "pkts_toclient":
                120,

            "bytes_toserver":
                15000,

            "bytes_toclient":
                120000,

            "start":
                "2023-01-01T12:00:00.000000+0000",

            "end":
                "2023-01-01T12:00:05.500000+0000",

            "age":
                5.5,
        },
    }

    # ---------------------------------------------------------------
    # Extract
    # ---------------------------------------------------------------

    print("\nFeature values:")

    features = extractor.extract_from_event(
        sample_event
    )

    if features is None:

        print(
            "ERROR: Feature extraction failed."
        )

        return

    values = features.to_array()

    for name, value in zip(
        FEATURE_COLUMNS,
        values,
    ):

        print(
            f"  {name}: {value}"
        )

    print(
        f"\nFeature count: {len(values)}"
    )

    # ---------------------------------------------------------------
    # Test scaling
    # ---------------------------------------------------------------

    print(
        "\nTesting scaler..."
    )

    scaled = extractor.extract_and_scale(
        sample_event
    )

    if scaled is not None:

        print(
            "Scaler test: SUCCESS"
        )

        print(
            f"Scaled feature count: {len(scaled)}"
        )

    else:

        print(
            "Scaler test: FAILED"
        )

    # ---------------------------------------------------------------
    # Test model compatibility
    # ---------------------------------------------------------------

    print(
        "\nTesting trained model compatibility..."
    )

    compatible = extractor.validate_model_compatibility(
        "models/xgboost.joblib"
    )

    print(
        f"Model compatible: {compatible}"
    )

    print("\n" + "=" * 70)
    print("TEST COMPLETE")
    print("=" * 70)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    main()