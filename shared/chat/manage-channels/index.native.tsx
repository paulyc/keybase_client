import * as React from 'react'
import {
  Avatar,
  Text,
  Box,
  ClickableBox,
  ProgressIndicator,
  ScrollView,
  Checkbox,
  Icon,
  HeaderHoc,
  WaitingButton,
} from '../../common-adapters'
import {globalStyles, globalColors, globalMargins, platformStyles} from '../../styles'
import {Props, RowProps} from './index.types'

const Edit = ({onClick, style}: {onClick: () => void; style: Object}) => (
  <ClickableBox style={style} onClick={onClick}>
    <Icon style={{marginRight: globalMargins.xtiny}} type="iconfont-edit" sizeType="Small" />
    <Text type="BodySmallPrimaryLink">Edit</Text>
  </ClickableBox>
)

const Row = (
  props: RowProps & {
    canEditChannels: boolean
    selected: boolean
    onToggle: () => void
    showEdit: boolean
    onEdit: () => void
    onClickChannel: () => void
  }
) => (
  <Box style={_rowBox}>
    <Checkbox
      disabled={props.name.toLowerCase() === 'general'}
      style={{alignSelf: 'flex-end'}}
      checked={props.selected}
      label=""
      onCheck={props.onToggle}
    />
    <Box
      style={{...globalStyles.flexBoxColumn, flex: 1, paddingLeft: globalMargins.tiny, position: 'relative'}}
    >
      <Text
        type="BodySemiboldLink"
        onClick={props.onClickChannel}
        style={{color: globalColors.blue, maxWidth: '100%'}}
        lineClamp={1}
      >
        #{props.name}
      </Text>
      <Text type="BodySmall" lineClamp={1}>
        {props.description}
      </Text>
    </Box>
    {props.showEdit && props.canEditChannels && (
      <Edit
        style={{
          ...globalStyles.flexBoxRow,
          alignItems: 'center',
          justifyContent: 'flex-end',
        }}
        onClick={props.onEdit}
      />
    )}
  </Box>
)

const _rowBox = {
  ...globalStyles.flexBoxRow,
  alignItems: 'center',
  flexShrink: 0,
  height: 56,
  padding: globalMargins.small,
  width: '100%',
}

const ManageChannels = (props: Props) => (
  <Box style={_boxStyle}>
    <ScrollView style={{alignSelf: 'flex-start', width: '100%'}}>
      {props.canCreateChannels && (
        <Box style={_createStyle}>
          <Icon style={_createIcon} type="iconfont-new" onClick={props.onCreate} color={globalColors.blue} />
          <Text type="BodyBigLink" onClick={props.onCreate}>
            New chat channel
          </Text>
        </Box>
      )}
      {props.channels.map(c => (
        <Row
          key={c.convID}
          canEditChannels={props.canEditChannels}
          description={c.description}
          name={c.name}
          selected={props.nextChannelState[c.convID]}
          onToggle={() => props.onToggle(c.convID)}
          showEdit={!props.unsavedSubscriptions}
          onEdit={() => props.onEdit(c.convID)}
          onClickChannel={() => props.onClickChannel(c.name)}
        />
      ))}
    </ScrollView>
    <Box
      style={{
        borderStyle: 'solid',
        borderTopColor: globalColors.black_10,
        borderTopWidth: 1,
        ...globalStyles.flexBoxColumn,
        justifyContent: 'flex-end',
        padding: globalMargins.small,
      }}
    >
      <Box style={{...globalStyles.flexBoxRow, justifyContent: 'center'}}>
        <WaitingButton
          fullWidth={true}
          label={props.unsavedSubscriptions ? 'Save' : 'Saved'}
          waitingKey={props.waitingKey}
          disabled={!props.unsavedSubscriptions}
          onClick={props.onSaveSubscriptions}
        />
      </Box>
    </Box>
  </Box>
)

const Header = (props: Props) => {
  let channelDisplay
  if (props.channels.length === 0 || props.waitingForGet) {
    channelDisplay = <ProgressIndicator style={{width: 48}} />
  } else {
    channelDisplay = (
      <Text type="BodyBig">
        {props.channels.length} {props.channels.length !== 1 ? 'chat channels' : 'chat channel'}
      </Text>
    )
  }
  return (
    <Box style={_headerStyle}>
      <Box style={{...globalStyles.flexBoxRow, alignItems: 'center', height: 15}}>
        <Avatar isTeam={true} teamname={props.teamname} size={16} />
        <Text
          type="BodySmallSemibold"
          style={platformStyles({isMobile: {fontSize: 11, lineHeight: 16, marginLeft: globalMargins.xtiny}})}
          lineClamp={1}
        >
          {props.teamname}
        </Text>
      </Box>
      {channelDisplay}
    </Box>
  )
}

const _headerStyle = {
  ...globalStyles.fillAbsolute,
  ...globalStyles.flexBoxColumn,
  alignItems: 'center',
}

const _boxStyle = {
  ...globalStyles.flexBoxColumn,
  backgroundColor: globalColors.white,
  height: '100%',
  width: '100%',
}

const _createStyle = {
  ...globalStyles.flexBoxRow,
  alignItems: 'center',
  alignSelf: 'stretch',
  height: 56,
  justifyContent: 'center',
}

const _createIcon = {
  marginRight: globalMargins.xtiny,
}

const Wrapper = (p: Props) => <ManageChannels {...p} onClose={undefined} />

export default HeaderHoc(Wrapper)
