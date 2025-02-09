import AssetInput from '.'
import * as WalletsGen from '../../../actions/wallets-gen'
import {namedConnect} from '../../../util/container'
import * as RouteTreeGen from '../../../actions/route-tree-gen'
import * as Constants from '../../../constants/wallets'

type OwnProps = {}

const mapStateToProps = state => {
  const {amount, currency} = state.wallets.building
  return {
    bottomLabel: '', // TODO
    currencyLoading: currency === '',
    displayUnit: currency,
    // TODO differentiate between an asset (7 digits) and a display currency (2 digits) below
    inputPlaceholder: currency !== 'XLM' ? '0.00' : '0.0000000',
    numDecimalsAllowed: currency !== 'XLM' ? 2 : 7,
    topLabel: '', // TODO
    value: amount,
  }
}

const mapDispatchToProps = dispatch => ({
  onChangeAmount: (amount: string) => dispatch(WalletsGen.createSetBuildingAmount({amount})),
  onChangeDisplayUnit: () => {
    dispatch(
      RouteTreeGen.createNavigateAppend({
        path: [
          {
            props: {},
            selected: Constants.chooseAssetFormRouteKey,
          },
        ],
      })
    )
  },
})

const mergeProps = (stateProps, dispatchProps) => ({
  bottomLabel: stateProps.bottomLabel,
  currencyLoading: stateProps.currencyLoading,
  displayUnit: stateProps.displayUnit,
  inputPlaceholder: stateProps.inputPlaceholder,
  numDecimalsAllowed: stateProps.numDecimalsAllowed,
  onChangeAmount: dispatchProps.onChangeAmount,
  onChangeDisplayUnit: dispatchProps.onChangeDisplayUnit,
  topLabel: stateProps.topLabel,
  value: stateProps.value,
})

export default namedConnect(mapStateToProps, mapDispatchToProps, mergeProps, 'AssetInput')(AssetInput)
