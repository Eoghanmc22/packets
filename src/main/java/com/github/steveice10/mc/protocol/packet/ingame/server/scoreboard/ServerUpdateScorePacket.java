package com.github.steveice10.mc.protocol.packet.ingame.server.scoreboard;

import com.github.steveice10.mc.protocol.data.MagicValues;
import com.github.steveice10.mc.protocol.data.game.scoreboard.ScoreboardAction;
import com.github.steveice10.packetlib.io.NetInput;
import com.github.steveice10.packetlib.io.NetOutput;
import com.github.steveice10.packetlib.packet.Packet;
import lombok.AccessLevel;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.io.IOException;

@Data
@Setter(AccessLevel.NONE)
@NoArgsConstructor()
public class ServerUpdateScorePacket implements Packet {
    private String entry;
    private ScoreboardAction action;
    private String objective;
    private int value;

    public ServerUpdateScorePacket(String entry, String objective) {
        this.entry = entry;
        this.action = ScoreboardAction.REMOVE;
        this.objective = objective;
    }

    public ServerUpdateScorePacket(String entry, String objective, int value) {
        this.entry = entry;
        this.action = ScoreboardAction.ADD_OR_UPDATE;
        this.objective = objective;

        this.value = value;
    }

    @Override
    public void read(NetInput in) throws IOException {
        this.entry = in.readString();
        this.action = MagicValues.key(ScoreboardAction.class, in.readVarInt());
        this.objective = in.readString();
        if(this.action == ScoreboardAction.ADD_OR_UPDATE) {
            this.value = in.readVarInt();
        }
    }

    @Override
    public void write(NetOutput out) throws IOException {
        out.writeString(this.entry);
        out.writeVarInt(MagicValues.value(Integer.class, this.action));
        out.writeString(this.objective);
        if(this.action == ScoreboardAction.ADD_OR_UPDATE) {
            out.writeVarInt(this.value);
        }
    }

    @Override
    public boolean isPriority() {
        return false;
    }
}
