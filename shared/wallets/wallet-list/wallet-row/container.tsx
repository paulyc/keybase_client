import {WalletRow, Props} from '.'
import {connect, isMobile} from '../../../util/container'
import {getAccount, getSelectedAccount} from '../../../constants/wallets'
import * as WalletsGen from '../../../actions/wallets-gen'
import * as RouteTreeGen from '../../../actions/route-tree-gen'
import {AccountID} from '../../../constants/types/wallets'

// TODO: This is now desktop-only, so remove references to isMobile.

type OwnProps = {
  accountID: AccountID
}

const mapStateToProps = (
  state,
  ownProps: {
    accountID: AccountID
  }
) => {
  const account = getAccount(state, ownProps.accountID)
  const name = account.name
  const me = state.config.username || ''
  const keybaseUser = account.isDefault ? me : ''
  const selectedAccount = getSelectedAccount(state)
  // const path = RouteTree.getPath(state.routeTree.routeState).last()
  const airdropSelected = false // TODO path === 'airdrop' || path === 'airdropQualify'

  return {
    contents: account.balanceDescription,
    isSelected: !airdropSelected && selectedAccount === ownProps.accountID,
    keybaseUser,
    name,
    selectedAccount,
    unreadPayments: state.wallets.unreadPaymentsMap.get(ownProps.accountID, 0),
  }
}

const mapDispatchToProps = dispatch => ({
  _onClearNewPayments: (accountID: AccountID) => dispatch(WalletsGen.createClearNewPayments({accountID})),
  _onSelectAccount: (accountID: AccountID) => {
    if (!isMobile) {
      dispatch(RouteTreeGen.createNavUpToScreen({routeName: 'wallet'}))
    }
    dispatch(WalletsGen.createSelectAccount({accountID, reason: 'user-selected', show: true}))
  },
})

const mergeProps = (stateProps, dispatchProps, ownProps): Props => ({
  contents: stateProps.contents,
  isSelected: !isMobile && stateProps.isSelected,
  keybaseUser: stateProps.keybaseUser,
  name: stateProps.name,
  onSelect: () => {
    // First clear any new payments on the currently selected acct.
    dispatchProps._onClearNewPayments(stateProps.selectedAccount)
    dispatchProps._onSelectAccount(ownProps.accountID)
  },
  unreadPayments: stateProps.unreadPayments,
})

export default connect(
  mapStateToProps,
  mapDispatchToProps,
  mergeProps
)(WalletRow)
